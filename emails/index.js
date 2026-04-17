// ============================================================
// emails/index.js
// All transactional email HTML templates
// Used by billing.js, auth.js and cron.js
// ============================================================

const BASE = `
  <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
              max-width:560px;margin:0 auto;padding:40px 32px;background:#ffffff">
    <div style="margin-bottom:28px">
      <img src="https://getaishield.eu/icon.png" width="32" height="32"
           style="border-radius:8px;vertical-align:middle;margin-right:10px">
      <span style="font-weight:700;font-size:16px;color:#0D1117;vertical-align:middle">
        AI Shield
      </span>
    </div>
    {{BODY}}
    <hr style="border:none;border-top:1px solid #E3E8EF;margin:36px 0 24px">
    <p style="color:#9CA3AF;font-size:12px;line-height:1.5;margin:0">
      AI Shield by Koller Group &nbsp;·&nbsp;
      <a href="https://getaishield.eu" style="color:#9CA3AF">getaishield.eu</a>
    </p>
  </div>
`;

function wrap(body) {
  return BASE.replace('{{BODY}}', body);
}

function btn(text, url) {
  return `
    <a href="${url}"
       style="display:inline-block;background:#0052CC;color:#ffffff;font-weight:600;
              font-size:14px;padding:12px 24px;border-radius:8px;text-decoration:none;
              margin-top:8px">
      ${text}
    </a>
  `;
}

function h1(text) {
  return `<h1 style="font-size:22px;font-weight:800;color:#0D1117;
                     margin:0 0 12px;line-height:1.2">${text}</h1>`;
}

function p(text) {
  return `<p style="color:#3A4250;font-size:15px;line-height:1.65;margin:0 0 20px">${text}</p>`;
}

// ──────────────────────────────────────────────────────────
// 1. WELCOME — sent on signup
// ──────────────────────────────────────────────────────────
function welcome(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${h1('Your 14-day trial has started. 🛡️')}
    ${p(`Hi ${name}, welcome to AI Shield.`)}
    ${p(`Your team is now protected from accidental data leaks to ChatGPT, Claude, Gemini and 25+ AI tools. Every sensitive data event is logged, blocked, and ready for your GDPR audit trail.`)}
    ${p('Here\'s what to do next:')}
    <ol style="color:#3A4250;font-size:14px;line-height:1.8;padding-left:20px;margin:0 0 24px">
      <li>Install the Chrome extension on your team's browsers</li>
      <li>Open your dashboard to see detections in real-time</li>
      <li>Review your compliance status before the EU AI Act deadline</li>
    </ol>
    ${btn('Open Dashboard →', 'https://getaishield.eu/dashboard')}
    <p style="color:#9CA3AF;font-size:13px;margin-top:20px">
      Your trial ends in 14 days. No charge until you choose a plan.
    </p>
  `);
}

// ──────────────────────────────────────────────────────────
// 2. TRIAL ENDING — sent 3 days before expiry
// ──────────────────────────────────────────────────────────
function trialEnding(nameOrEmail, daysLeft) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const plural = daysLeft === 1 ? 'day' : 'days';
  return wrap(`
    ${h1(`⏳ Your trial ends in ${daysLeft} ${plural}.`)}
    ${p(`Hi ${name}, your AI Shield trial expires in <strong>${daysLeft} ${plural}</strong>.`)}
    ${p(`After your trial, AI Shield will stop monitoring your team's AI tool usage. Your compliance audit trail will no longer be updated, and GDPR detections will stop.`)}
    <table style="width:100%;border:1px solid #E3E8EF;border-radius:10px;
                  border-spacing:0;margin-bottom:24px;overflow:hidden">
      <tr>
        <td style="padding:14px 18px;border-bottom:1px solid #E3E8EF;
                   font-size:13px;font-weight:600;color:#0D1117">Essentials</td>
        <td style="padding:14px 18px;border-bottom:1px solid #E3E8EF;
                   font-size:13px;color:#0052CC;font-weight:700;text-align:right">€49/month</td>
      </tr>
      <tr>
        <td style="padding:14px 18px;border-bottom:1px solid #E3E8EF;
                   background:#F7F8FA;font-size:13px;font-weight:600;color:#0D1117">
          Compliance <span style="font-size:11px;background:#0052CC;color:white;
                                  padding:2px 7px;border-radius:4px;margin-left:6px">Popular</span>
        </td>
        <td style="padding:14px 18px;border-bottom:1px solid #E3E8EF;background:#F7F8FA;
                   font-size:13px;color:#0052CC;font-weight:700;text-align:right">€99/month</td>
      </tr>
      <tr>
        <td style="padding:14px 18px;font-size:13px;font-weight:600;color:#0D1117">Business</td>
        <td style="padding:14px 18px;font-size:13px;color:#0052CC;
                   font-weight:700;text-align:right">€249/month</td>
      </tr>
    </table>
    ${btn('Choose a plan →', 'https://getaishield.eu/pricing')}
    <p style="color:#9CA3AF;font-size:13px;margin-top:16px">
      Save 20% with annual billing. No lock-in — cancel anytime.
    </p>
  `);
}

// ──────────────────────────────────────────────────────────
// 3. TRIAL EXPIRED
// ──────────────────────────────────────────────────────────
function trialExpired(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${h1('Your trial has ended.')}
    ${p(`Hi ${name}, your 14-day AI Shield trial has expired.`)}
    ${p(`AI Shield is no longer monitoring your team's AI tool usage. Your data is still safe — we haven't deleted anything. Upgrade to reactivate protection immediately.`)}
    ${btn('Reactivate now →', 'https://getaishield.eu/pricing')}
    <p style="color:#9CA3AF;font-size:13px;margin-top:16px">
      Questions? Reply to this email and we'll help.
    </p>
  `);
}

// ──────────────────────────────────────────────────────────
// 4. PAYMENT CONFIRMED
// ──────────────────────────────────────────────────────────
function paymentConfirmed(nameOrEmail, plan, cycle) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  const cycleLabel = cycle === 'annual' ? 'Annual (20% off)' : 'Monthly';
  return wrap(`
    ${h1(`✅ ${planLabel} plan is active.`)}
    ${p(`Hi ${name}, your AI Shield subscription is confirmed.`)}
    <table style="width:100%;background:#F7F8FA;border-radius:10px;
                  border-spacing:0;margin-bottom:24px">
      <tr>
        <td style="padding:14px 18px;font-size:13px;color:#6B7280">Plan</td>
        <td style="padding:14px 18px;font-size:13px;font-weight:600;
                   color:#0D1117;text-align:right">${planLabel}</td>
      </tr>
      <tr>
        <td style="padding:14px 18px;font-size:13px;color:#6B7280">Billing</td>
        <td style="padding:14px 18px;font-size:13px;font-weight:600;
                   color:#0D1117;text-align:right">${cycleLabel}</td>
      </tr>
      <tr>
        <td style="padding:14px 18px;font-size:13px;color:#6B7280">Status</td>
        <td style="padding:14px 18px;font-size:13px;font-weight:600;
                   color:#12B76A;text-align:right">Active ✓</td>
      </tr>
    </table>
    ${p('Your team is fully protected. GDPR audit reports are available in your dashboard anytime.')}
    ${btn('Open Dashboard →', 'https://getaishield.eu/dashboard')}
    <p style="color:#9CA3AF;font-size:13px;margin-top:16px">
      To manage your subscription, update your card, or cancel —
      <a href="https://getaishield.eu/dashboard/billing" style="color:#0052CC">
        visit billing settings
      </a>.
    </p>
  `);
}

// ──────────────────────────────────────────────────────────
// 5. PAYMENT FAILED
// ──────────────────────────────────────────────────────────
function paymentFailed(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${h1('⚠️ Payment failed — action required')}
    ${p(`Hi ${name}, we couldn't process your AI Shield payment.`)}
    ${p(`Your subscription is currently on hold. Please update your payment method to reactivate protection for your team.`)}
    ${btn('Update payment method →', 'https://getaishield.eu/dashboard/billing')}
    <p style="color:#9CA3AF;font-size:13px;margin-top:16px">
      We'll retry the payment automatically. If it fails again,
      your subscription will be cancelled.
    </p>
  `);
}

module.exports = {
  welcome,
  trialEnding,
  trialExpired,
  paymentConfirmed,
  paymentFailed,
};
