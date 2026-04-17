// ============================================================
// routes/billing.js
// Stripe checkout, customer portal, and webhook handler
//
// Mount in app.js:
//   app.use('/billing', require('./routes/billing'))
//
// IMPORTANT: The webhook endpoint needs raw body.
// In app.js, add BEFORE json middleware:
//   app.use('/billing/webhook', express.raw({ type: 'application/json' }))
// ============================================================

const express  = require('express');
const Stripe   = require('stripe');
const { Pool } = require('pg');
const { Resend } = require('resend');
const auth     = require('../middleware/auth');
const emails   = require('../emails');
const router   = express.Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── Stripe Price IDs ──────────────────────────────────────
// Fill these with your actual Stripe Price IDs
// Dashboard → Products → (product) → Pricing → Copy ID
const PRICE_IDS = {
  essentials_monthly:  process.env.STRIPE_PRICE_ESSENTIALS_MONTHLY,
  essentials_annual:   process.env.STRIPE_PRICE_ESSENTIALS_ANNUAL,
  compliance_monthly:  process.env.STRIPE_PRICE_COMPLIANCE_MONTHLY,
  compliance_annual:   process.env.STRIPE_PRICE_COMPLIANCE_ANNUAL,
  business_monthly:    process.env.STRIPE_PRICE_BUSINESS_MONTHLY,
  business_annual:     process.env.STRIPE_PRICE_BUSINESS_ANNUAL,
};

// Max users per plan (for the extension to validate)
const PLAN_LIMITS = {
  trial:      10,
  essentials: 10,
  compliance: 30,
  business:   75,
  enterprise: Infinity,
};

// ─── GET /billing/status ───────────────────────────────────
// Dashboard polls this to know current plan + days remaining
router.get('/status', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT plan, billing_cycle, status,
              trial_ends_at, current_period_end,
              stripe_subscription_id
       FROM subscriptions
       WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.userId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'No subscription found' });
    }

    const sub = rows[0];
    const now = new Date();

    // Days remaining in trial
    let trialDaysLeft = null;
    if (sub.status === 'trialing' && sub.trial_ends_at) {
      trialDaysLeft = Math.max(
        0,
        Math.ceil((new Date(sub.trial_ends_at) - now) / 86400000)
      );
    }

    res.json({
      plan:           sub.plan,
      billingCycle:   sub.billing_cycle,
      status:         sub.status,
      trialDaysLeft,
      periodEnd:      sub.current_period_end,
      maxUsers:       PLAN_LIMITS[sub.plan] || 10,
      isActive:       ['trialing', 'active'].includes(sub.status),
    });

  } catch (err) {
    console.error('GET /billing/status error:', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ─── POST /billing/checkout ────────────────────────────────
// Creates a Stripe Checkout Session and returns the redirect URL
// Body: { plan: 'compliance', cycle: 'annual' }
router.post('/checkout', auth, async (req, res) => {
  const { plan, cycle } = req.body;

  if (!plan || !cycle) {
    return res.status(400).json({ error: 'plan and cycle are required' });
  }

  const priceKey = `${plan}_${cycle}`;
  const priceId  = PRICE_IDS[priceKey];

  if (!priceId) {
    return res.status(400).json({
      error: `Invalid plan/cycle combination: ${priceKey}`,
      available: Object.keys(PRICE_IDS)
    });
  }

  try {
    // Get or create Stripe customer
    const { rows } = await pool.query(
      `SELECT stripe_customer_id FROM subscriptions WHERE user_id = $1`,
      [req.user.userId]
    );

    let customerId = rows[0]?.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        metadata: { userId: req.user.userId }
      });
      customerId = customer.id;

      // Save customer ID immediately
      await pool.query(
        `UPDATE subscriptions SET stripe_customer_id = $1
         WHERE user_id = $2`,
        [customerId, req.user.userId]
      );
    }

    const session = await stripe.checkout.sessions.create({
      customer:             customerId,
      mode:                 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      subscription_data: {
        metadata: {
          userId: req.user.userId,
          plan,
          cycle
        }
      },
      success_url: `${process.env.FRONTEND_URL}/dashboard?upgraded=true&plan=${plan}`,
      cancel_url:  `${process.env.FRONTEND_URL}/pricing?canceled=true`,
    });

    // Log
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, details)
       VALUES ($1, 'checkout_started', $2)`,
      [req.user.userId, JSON.stringify({ plan, cycle, sessionId: session.id })]
    );

    res.json({ url: session.url });

  } catch (err) {
    console.error('POST /billing/checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// ─── POST /billing/portal ──────────────────────────────────
// Opens Stripe Customer Portal (manage plan, cancel, update card)
router.post('/portal', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT stripe_customer_id FROM subscriptions WHERE user_id = $1`,
      [req.user.userId]
    );

    const customerId = rows[0]?.stripe_customer_id;

    if (!customerId) {
      return res.status(400).json({
        error: 'No Stripe customer found. You need an active subscription first.'
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: `${process.env.FRONTEND_URL}/dashboard`,
    });

    res.json({ url: session.url });

  } catch (err) {
    console.error('POST /billing/portal error:', err);
    res.status(500).json({ error: 'Failed to open billing portal' });
  }
});

// ─── POST /billing/webhook ─────────────────────────────────
// Stripe sends events here. Must receive raw body (not JSON-parsed).
// In app.js: app.use('/billing/webhook', express.raw({ type: 'application/json' }))
router.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`[Stripe webhook] ${event.type}`);

  try {
    switch (event.type) {

      // ── Payment succeeded → activate plan
      case 'checkout.session.completed': {
        const session  = event.data.object;
        const userId   = session.metadata?.userId;
        const plan     = session.metadata?.plan;
        const cycle    = session.metadata?.cycle;

        if (!userId || !plan) {
          console.warn('checkout.session.completed: missing metadata', session.metadata);
          break;
        }

        // Get subscription details from Stripe
        const stripeSub = await stripe.subscriptions.retrieve(session.subscription);

        await pool.query(
          `UPDATE subscriptions
           SET stripe_customer_id     = $1,
               stripe_subscription_id = $2,
               stripe_price_id        = $3,
               plan                   = $4,
               billing_cycle          = $5,
               status                 = 'active',
               current_period_start   = to_timestamp($6),
               current_period_end     = to_timestamp($7)
           WHERE user_id = $8`,
          [
            session.customer,
            session.subscription,
            stripeSub.items.data[0]?.price.id,
            plan,
            cycle || 'monthly',
            stripeSub.current_period_start,
            stripeSub.current_period_end,
            userId
          ]
        );

        // Log
        await pool.query(
          `INSERT INTO audit_logs (user_id, action, details)
           VALUES ($1, 'upgrade', $2)`,
          [userId, JSON.stringify({ plan, cycle, stripeSubscriptionId: session.subscription })]
        );

        // Send confirmation email
        const { rows } = await pool.query(
          'SELECT email, name FROM users WHERE id = $1', [userId]
        );
        if (rows[0]) {
          await sendEmail(resend, {
            to: rows[0].email,
            subject: `AI Shield ${capitalise(plan)} — subscription confirmed ✅`,
            html: emails.paymentConfirmed(rows[0].name || rows[0].email, plan, cycle)
          });
        }
        break;
      }

      // ── Subscription renewed or changed
      case 'customer.subscription.updated': {
        const sub = event.data.object;

        await pool.query(
          `UPDATE subscriptions
           SET status               = $1,
               current_period_start = to_timestamp($2),
               current_period_end   = to_timestamp($3),
               stripe_price_id      = $4
           WHERE stripe_subscription_id = $5`,
          [
            sub.status,
            sub.current_period_start,
            sub.current_period_end,
            sub.items.data[0]?.price.id,
            sub.id
          ]
        );
        break;
      }

      // ── Subscription cancelled
      case 'customer.subscription.deleted': {
        const sub = event.data.object;

        await pool.query(
          `UPDATE subscriptions
           SET status       = 'canceled',
               canceled_at  = NOW()
           WHERE stripe_subscription_id = $1`,
          [sub.id]
        );
        break;
      }

      // ── Payment failed
      case 'invoice.payment_failed': {
        const invoice = event.data.object;

        await pool.query(
          `UPDATE subscriptions
           SET status = 'past_due'
           WHERE stripe_customer_id = $1`,
          [invoice.customer]
        );
        break;
      }

      // ── Invoice paid (renewal)
      case 'invoice.paid': {
        const invoice = event.data.object;
        if (invoice.billing_reason === 'subscription_cycle') {
          await pool.query(
            `UPDATE subscriptions SET status = 'active'
             WHERE stripe_customer_id = $1`,
            [invoice.customer]
          );
        }
        break;
      }

      default:
        // Unhandled event — ignore
        break;
    }

    res.json({ received: true });

  } catch (err) {
    console.error(`[Stripe webhook] Error processing ${event.type}:`, err);
    // Return 200 so Stripe doesn't retry — log for manual review
    res.json({ received: true, warning: 'Processing error logged' });
  }
});

// ─── Helpers ───────────────────────────────────────────────
async function sendEmail(resend, { to, subject, html }) {
  try {
    await resend.emails.send({
      from: `AI Shield <hello@${process.env.EMAIL_DOMAIN || 'getaishield.eu'}>`,
      to,
      subject,
      html
    });
  } catch (err) {
    console.error('Failed to send email:', err.message);
  }
}

function capitalise(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

module.exports = router;
