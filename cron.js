// ============================================================
// cron.js
// Daily cron jobs for trial emails and expiration
//
// Add to Railway as a separate service OR require in app.js:
//   require('./cron')
//
// Dependencies: npm install node-cron
// ============================================================

const cron   = require('node-cron');
const { Pool } = require('pg');
const { Resend } = require('resend');
const emails = require('./emails');

const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);

const FROM = `AI Shield <hello@${process.env.EMAIL_DOMAIN || 'getaishield.eu'}>`;

// ─── Helper: send and log email ────────────────────────────
async function sendOnce(userId, emailType, to, subject, html) {
  // Check if already sent this type today
  const { rows } = await pool.query(
    `SELECT id FROM email_log
     WHERE user_id = $1 AND email_type = $2
       AND sent_at > NOW() - INTERVAL '20 hours'`,
    [userId, emailType]
  );
  if (rows.length > 0) return; // already sent, skip

  try {
    await resend.emails.send({ from: FROM, to, subject, html });
    await pool.query(
      `INSERT INTO email_log (user_id, email_type) VALUES ($1, $2)`,
      [userId, emailType]
    );
    console.log(`[CRON] Sent ${emailType} to ${to}`);
  } catch (err) {
    console.error(`[CRON] Failed to send ${emailType} to ${to}:`, err.message);
  }
}

// ─── Job 1: Trial ending in 3 days ─────────────────────────
// Runs every day at 09:00 UTC
cron.schedule('0 9 * * *', async () => {
  console.log('[CRON] Checking trials ending in 3 days...');
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.email, u.name, s.trial_ends_at
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.status = 'trialing'
        AND s.trial_ends_at BETWEEN NOW() + INTERVAL '2 days'
                                AND NOW() + INTERVAL '4 days'
    `);

    for (const row of rows) {
      const daysLeft = Math.ceil(
        (new Date(row.trial_ends_at) - Date.now()) / 86400000
      );
      await sendOnce(
        row.id,
        'trial_ending_3d',
        row.email,
        `Your AI Shield trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`,
        emails.trialEnding(row.name || row.email, daysLeft)
      );
    }
  } catch (err) {
    console.error('[CRON] trial_ending_3d error:', err);
  }
});

// ─── Job 2: Trial ending in 1 day ──────────────────────────
// Runs every day at 09:00 UTC (same schedule, different window)
cron.schedule('0 9 * * *', async () => {
  console.log('[CRON] Checking trials ending tomorrow...');
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.email, u.name, s.trial_ends_at
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      WHERE s.status = 'trialing'
        AND s.trial_ends_at BETWEEN NOW()
                                AND NOW() + INTERVAL '25 hours'
    `);

    for (const row of rows) {
      await sendOnce(
        row.id,
        'trial_ending_1d',
        row.email,
        'Your AI Shield trial ends tomorrow — choose your plan',
        emails.trialEnding(row.name || row.email, 1)
      );
    }
  } catch (err) {
    console.error('[CRON] trial_ending_1d error:', err);
  }
});

// ─── Job 3: Mark expired trials + send expired email ───────
// Runs every hour to catch exact expiry times
cron.schedule('0 * * * *', async () => {
  console.log('[CRON] Expiring overdue trials...');
  try {
    // Get trials that just expired (not yet marked)
    const { rows } = await pool.query(`
      UPDATE subscriptions
      SET status = 'expired', updated_at = NOW()
      WHERE status = 'trialing'
        AND trial_ends_at < NOW()
      RETURNING user_id
    `);

    for (const row of rows) {
      const user = await pool.query(
        'SELECT email, name FROM users WHERE id = $1', [row.user_id]
      );
      if (user.rows[0]) {
        await sendOnce(
          row.user_id,
          'trial_expired',
          user.rows[0].email,
          'Your AI Shield trial has ended',
          emails.trialExpired(user.rows[0].name || user.rows[0].email)
        );
      }
    }

    if (rows.length > 0) {
      console.log(`[CRON] Expired ${rows.length} trial(s)`);
    }
  } catch (err) {
    console.error('[CRON] expire_trials error:', err);
  }
});

console.log('[CRON] Jobs scheduled: trial_ending_3d, trial_ending_1d, expire_trials');
