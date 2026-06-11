// ============================================================
// emails/index.js
// All transactional email HTML templates — responsive + branded
//
// // Version: 3.0.0  ← NEW (deep linking support)
//
/**
 * AI Shield — Email Templates v3.0.0
 * * v3.0.0 changes:
 * - All dashboard links now use deep linking (#hash)
 * - /dashboard/billing → /dashboard.html#billing
 * - /dashboard → /dashboard.html
 */
// ============================================================

const LOGO_URL = 'https://www.getaishield.co/logo_full.png';
const APP_URL  = 'https://getaishield.co';
const CHROME_STORE_URL = 'https://chromewebstore.google.com/detail/ai-shield-compliance-audi/chefkknkoninpbplimnaekjldgjgipnj';

// ─── BASE TEMPLATE — Responsive + brand-aligned ───────────
const BASE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  body { margin: 0; padding: 0; background: #F7F8FA; }
  a { color: #0052CC; }
  table { border-collapse: collapse; }
  img { border: 0; display: block; max-width: 100%; height: auto; }

  @media only screen and (max-width: 600px) {
    .email-wrapper { padding: 16px 12px !important; }
    .email-container { border-radius: 12px !important; }
    .email-body { padding: 22px 18px !important; }
    .email-header { padding: 22px 18px 0 18px !important; }
    .email-footer { padding: 0 18px 22px 18px !important; }

    .h1 { font-size: 19px !important; line-height: 1.3 !important; }
    .h2 { font-size: 14px !important; }
    .body-text { font-size: 14px !important; }
    .small-text { font-size: 12px !important; }
    .quote-text { font-size: 13px !important; line-height: 1.55 !important; }

    .stat-row { display: block !important; }
    .stat-cell {
      display: block !important;
      width: auto !important;
      box-sizing: border-box !important;
      margin: 0 0 6px 0 !important;
    }
    .stat-value { font-size: 22px !important; }

    .plan-name { font-size: 18px !important; }
    .plan-price { font-size: 22px !important; }

    .button-table { width: 100% !important; }
    .button-link {
      display: block !important;
      width: auto !important;
      text-align: center !important;
      padding: 12px 18px !important;
      font-size: 14px !important;
    }

    .footer-cell-left,
    .footer-cell-right {
      display: block !important;
      width: 100% !important;
      text-align: left !important;
      padding: 4px 0 !important;
    }
    .footer-cell-right { padding-top: 12px !important; }

    .step-number { width: 22px !important; height: 22px !important; line-height: 22px !important; font-size: 11px !important; }
    .step-title { font-size: 13px !important; }
    .step-desc { font-size: 12px !important; line-height: 1.5 !important; }

    .table-cell { padding: 10px 12px !important; font-size: 13px !important; }

    .info-block { padding: 12px 14px !important; }

    .code-display { font-size: 26px !important; padding: 18px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#F7F8FA;
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
       class="email-wrapper"
       style="background:#F7F8FA;padding:32px 16px;">
<tr><td align="center">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600"
       class="email-container"
       style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;
              box-shadow:0 2px 8px rgba(0,0,0,0.04);overflow:hidden;">

<tr><td class="email-header" style="padding:32px 36px 0 36px;">
  <img src="${LOGO_URL}" alt="AI Shield"
       style="height:30px;display:block;border:0;">
</td></tr>

<tr><td class="email-body" style="padding:24px 36px 32px 36px;">
{{BODY}}
</td></tr>

<tr><td class="email-footer" style="padding:0 36px 32px 36px;">
  <hr style="border:none;border-top:1px solid #E3E8EF;margin:0 0 18px 0;">
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
      <td class="footer-cell-left" style="vertical-align:middle;width:70%;">
        <p class="small-text" style="color:#9CA3AF;font-size:12px;line-height:1.5;margin:0;
                  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          <strong style="color:#6B7280;">AI Shield</strong> by Koller Group<br>
          <a href="${APP_URL}" style="color:#9CA3AF;text-decoration:none;">getaishield.co</a>
        </p>
      </td>
      <td class="footer-cell-right" style="text-align:right;vertical-align:middle;width:30%;">
        <img src="${LOGO_URL}" alt="AI Shield"
             style="height:16px;opacity:0.4;display:inline-block;border:0;">
      </td>
    </tr>
  </table>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;

function wrap(body) { return BASE.replace('{{BODY}}', body); }

function btn(text, url) {
  return `
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" class="button-table" style="margin:8px 0 0 0;">
      <tr><td style="border-radius:8px;background:#0052CC;">
        <a href="${url}" class="button-link"
           style="display:inline-block;background:#0052CC;color:#ffffff;
                  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                  font-weight:600;font-size:14px;padding:13px 26px;
                  border-radius:8px;text-decoration:none;
                  border:1px solid #0052CC;">${text}</a>
      </td></tr>
    </table>
  `;
}

function h1(text) {
  return `<h1 class="h1" style="font-family:'Syne',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                     font-size:22px;font-weight:800;color:#0D1117;
                     margin:0 0 12px 0;line-height:1.25;
                     letter-spacing:-0.02em;">${text}</h1>`;
}

function h2(text) {
  return `<h2 class="h2" style="font-family:'Syne',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                     font-size:15px;font-weight:700;color:#0D1117;
                     margin:22px 0 12px 0;line-height:1.3;
                     letter-spacing:-0.01em;">${text}</h2>`;
}

function p(text) {
  return `<p class="body-text" style="color:#3A4250;font-size:15px;line-height:1.6;margin:0 0 16px 0;
                    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">${text}</p>`;
}

function pSmall(text) {
  return `<p class="small-text" style="color:#9CA3AF;font-size:13px;line-height:1.6;margin:16px 0 0 0;
                    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">${text}</p>`;
}

function alertBanner(text, type = 'warning') {
  const styles = {
    warning: { bg: '#FFF8E1', border: '#FFD54F', color: '#7A5800' },
    danger:  { bg: '#FEE4E2', border: '#FFA48E', color: '#9B2226' },
    success: { bg: '#ECFDF5', border: '#A7F3D0', color: '#065F46' },
  };
  const s = styles[type] || styles.warning;
  return `
    <div style="background:${s.bg};border:1px solid ${s.border};border-radius:8px;
                padding:11px 14px;margin:0 0 20px 0;">
      <p class="small-text" style="margin:0;font-size:13px;font-weight:700;color:${s.color};
                font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">${text}</p>
    </div>
  `;
}

function statCard(value, label, color = '#0052CC') {
  return `
    <td class="stat-cell"
        style="background:#F7F8FA;border-radius:10px;padding:16px 12px;text-align:center;width:33.33%;">
      <div class="stat-value"
           style="font-family:'Syne',-apple-system,sans-serif;
                  font-size:26px;font-weight:800;color:${color};line-height:1;
                  letter-spacing:-0.02em;">${value}</div>
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                  font-size:10px;color:#9CA3AF;margin-top:6px;
                  text-transform:uppercase;letter-spacing:.07em;font-weight:600;">${label}</div>
    </td>
  `;
}

// Code block display (for company code)
function codeBlock(code) {
  return `
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#F7F8FA;border:2px dashed #C8D6F0;border-radius:12px;
                  border-spacing:0;margin:0 0 20px 0;">
      <tr><td style="padding:22px;text-align:center;">
        <div style="font-family:-apple-system,sans-serif;
                    font-size:11px;color:#9CA3AF;font-weight:600;
                    letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px;">
          Company Code
        </div>
        <div class="code-display"
             style="font-family:'Syne',Menlo,Monaco,monospace;
                    font-size:32px;font-weight:800;color:#0052CC;
                    letter-spacing:.14em;line-height:1;">
          ${code}
        </div>
        <div style="font-family:-apple-system,sans-serif;
                    font-size:12px;color:#6B7280;margin-top:12px;line-height:1.5;">
          Share this code with your team to activate the extension
        </div>
      </td></tr>
    </table>
  `;
}

// ──────────────────────────────────────────────────────────
// EMAIL TEMPLATES
// ──────────────────────────────────────────────────────────

function welcome(nameOrEmail, companyCode) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${h1('Your 14-day trial has started 🛡️')}
    ${p(`Hi ${name}, welcome to AI Shield.`)}
    ${p(`Your team is now protected from accidental data leaks to ChatGPT, Claude, Gemini and 25+ AI tools. Every sensitive data event is logged, blocked, and ready for your GDPR audit trail.`)}

    ${companyCode ? codeBlock(companyCode) : ''}

    ${h2(`Here's what to do next:`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom:24px;">
      ${[
        ['1', 'Share your Company Code', 'Send the code above to your team members so they can install the extension.'],
        ['2', 'Install the Chrome extension', `Each team member can <a href="${CHROME_STORE_URL}" style="color:#0052CC; text-decoration:underline;">install the extension here</a> in under 60 seconds. No IT team required.`],
        ['3', 'Open your dashboard', 'See detections in real-time as your team uses AI tools.']
      ].map(([num, title, desc], i, arr) => `
      <tr><td style="padding:10px 0;${i < arr.length - 1 ? 'border-bottom:1px solid #E3E8EF;' : ''}">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr>
            <td valign="top" style="width:30px;">
              <div class="step-number" style="width:24px;height:24px;background:#0052CC;border-radius:6px;
                          color:white;font-weight:700;font-size:12px;text-align:center;line-height:24px;
                          font-family:-apple-system,sans-serif;">${num}</div>
            </td>
            <td style="padding-left:12px;">
              <div class="step-title" style="font-size:14px;font-weight:600;color:#0D1117;
                          font-family:-apple-system,sans-serif;">${title}</div>
              <div class="step-desc" style="font-size:13px;color:#6B7280;line-height:1.5;
                          font-family:-apple-system,sans-serif;">${desc}</div>
            </td>
          </tr>
        </table>
      </td></tr>
      `).join('')}
    </table>

    ${btn('Open Dashboard →', `${APP_URL}/dashboard.html`)}
    ${pSmall('Your trial ends in 14 days. No charge until you choose a plan.')}
  `);
}

function employeeWelcome(nameOrEmail, companyName) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${alertBanner('✓ Your AI Shield protection is active', 'success')}

    ${h1(`You're protected, ${name}.`)}
    ${p(`You've successfully joined <strong style="color:#0D1117;">${companyName}</strong> on AI Shield. Your Chrome extension is now active and will protect you when using AI tools at work.`)}

    ${h2('How AI Shield protects you:')}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom:24px;">
      ${[
        ['🔍', 'Real-time scanning', 'When you type in ChatGPT, Claude, Gemini or 25+ AI tools, AI Shield checks for sensitive data before it leaves your browser.'],
        ['⚠️', 'Smart alerts', 'If you accidentally include a credit card, IBAN, API key, or other sensitive data, you\'ll see an alert with one click to remove it.'],
        ['🛡️', 'Privacy-first', 'AI Shield never reads or stores the content of your AI conversations. Only detections and your actions are logged for compliance.']
      ].map(([icon, title, desc], i, arr) => `
      <tr><td style="padding:12px 0;${i < arr.length - 1 ? 'border-bottom:1px solid #E3E8EF;' : ''}">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
          <tr>
            <td valign="top" style="width:32px;font-size:20px;line-height:1;padding-top:2px;">
              ${icon}
            </td>
            <td style="padding-left:10px;">
              <div class="step-title" style="font-size:14px;font-weight:600;color:#0D1117;
                          font-family:-apple-system,sans-serif;margin-bottom:2px;">${title}</div>
              <div class="step-desc" style="font-size:13px;color:#6B7280;line-height:1.55;
                          font-family:-apple-system,sans-serif;">${desc}</div>
            </td>
          </tr>
        </table>
      </td></tr>
      `).join('')}
    </table>

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#F7F8FA;border-left:3px solid #0052CC;border-radius:0 8px 8px 0;
                  border-spacing:0;margin:0 0 24px 0;">
      <tr><td class="info-block" style="padding:16px 18px;">
        <p class="small-text" style="margin:0;font-family:-apple-system,sans-serif;
                  font-size:12px;font-weight:700;color:#0D1117;
                  text-transform:uppercase;letter-spacing:0.07em;margin-bottom:6px;">
          Quick tip
        </p>
        <p class="body-text" style="margin:0;font-family:-apple-system,sans-serif;
                  font-size:13px;color:#3A4250;line-height:1.6;">
          When the AI Shield alert appears, take a moment to review what triggered it. Click <strong style="color:#0D1117;">"Remove data"</strong> if it's something sensitive — your compliance team will thank you.
        </p>
      </td></tr>
    </table>

    ${pSmall(`Questions about AI Shield? Reach out to your manager at ${companyName}, or visit <a href="${APP_URL}" style="color:#0052CC;">getaishield.co</a>.`)}
  `);
}

function trialDay7Checkin(nameOrEmail, stats = {}) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const { totalDetections = 0, totalBlocked = 0, activeEmployees = 0 } = stats;

  return wrap(`
    ${h1("You're halfway through your trial.")}
    ${p(`Hi ${name}, you've been using AI Shield for 7 days. Here's what we've protected so far:`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           class="stat-row"
           style="border-spacing:6px;border-collapse:separate;margin:0 -6px 24px -6px;">
      <tr>
        ${statCard(totalDetections, 'Detections', '#0052CC')}
        ${statCard(totalBlocked, 'Blocked', '#059669')}
        ${statCard(activeEmployees, 'Employees', '#0D1117')}
      </tr>
    </table>

    ${p('You have <strong style="color:#0D1117;">7 more days</strong> to explore AI Shield. Try these next:')}

    <ul class="body-text" style="color:#3A4250;font-size:14px;line-height:1.85;padding-left:20px;
               margin:0 0 24px 0;
               font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
      <li>Generate your first GDPR compliance report</li>
      <li>Invite the rest of your team to maximise coverage</li>
      <li>Customise detection rules for your industry</li>
    </ul>

    ${btn('Open Dashboard →', `${APP_URL}/dashboard.html`)}
    ${pSmall(`Questions? Reply to this email or <a href="https://cal.com/ai-shield/onboarding" style="color:#0052CC;">book a 15-min call</a>.`)}
  `);
}

function trialAddPayment(nameOrEmail, plan = 'compliance', daysLeft = 3) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  const planPrice = { essentials: 49, compliance: 99, business: 249 }[plan] || 99;
  const planUsers = { essentials: 10, compliance: 30, business: 75 }[plan] || 30;

  return wrap(`
    ${alertBanner(`⏰ ${daysLeft} ${daysLeft === 1 ? 'day' : 'days'} left in your trial`, 'warning')}

    ${h1('Keep your protection active.')}
    ${p(`Hi ${name}, your AI Shield trial ends soon. Add a payment method now to ensure uninterrupted protection — your team is already covered, and we'd hate for that to stop.`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#F7F8FA;border-radius:10px;border-spacing:0;margin:0 0 24px 0;">
      <tr>
        <td class="info-block" style="padding:18px 18px 12px 18px;">
          <div class="small-text" style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;text-transform:uppercase;
                      letter-spacing:.08em;font-weight:600;margin-bottom:6px;">
            YOUR PLAN
          </div>
          <div class="plan-name" style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:20px;font-weight:800;color:#0D1117;margin-bottom:2px;
                      letter-spacing:-0.02em;">${planLabel}</div>
          <div class="small-text" style="font-family:-apple-system,sans-serif;
                      font-size:13px;color:#6B7280;">Up to ${planUsers} users</div>
        </td>
      </tr>
      <tr>
        <td class="info-block" style="padding:14px 18px 18px 18px;border-top:1px solid #E3E8EF;">
          <div class="plan-price" style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:26px;font-weight:800;color:#0D1117;line-height:1;
                      letter-spacing:-0.02em;">
            €${planPrice}<span style="font-family:-apple-system,sans-serif;
                                    font-size:13px;color:#6B7280;font-weight:500;">/month</span>
          </div>
          <div class="small-text" style="font-family:-apple-system,sans-serif;
                      font-size:12px;color:#059669;font-weight:600;margin-top:6px;">
            💡 Save 20% by switching to annual billing
          </div>
        </td>
      </tr>
    </table>

    ${h2('Why teams keep AI Shield after the trial:')}

    <ul class="body-text" style="color:#3A4250;font-size:14px;line-height:1.85;padding-left:20px;
               margin:0 0 24px 0;
               font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
      <li><strong style="color:#0D1117;">Continuous compliance documentation</strong> for your DPO</li>
      <li><strong style="color:#0D1117;">EU AI Act readiness</strong> — audit reports anytime</li>
      <li><strong style="color:#0D1117;">Zero data leaks</strong> across 25+ AI platforms</li>
      <li><strong style="color:#0D1117;">Cancel anytime</strong> — no long contracts, no lock-in</li>
    </ul>

    ${btn('Add Payment Method →', `${APP_URL}/dashboard.html#billing`)}
    ${pSmall(`Want a different plan? <a href="${APP_URL}/pricing" style="color:#0052CC;">Compare plans</a>`)}
  `);
}

function trialEnding(nameOrEmail, daysLeft) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const plural = daysLeft === 1 ? 'day' : 'days';
  return wrap(`
    ${h1(`⏳ Your trial ends in ${daysLeft} ${plural}.`)}
    ${p(`Hi ${name}, your AI Shield trial expires in <strong>${daysLeft} ${plural}</strong>.`)}
    ${p(`After your trial, AI Shield will stop monitoring your team's AI tool usage. Your compliance audit trail will no longer be updated, and GDPR detections will stop.`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="border:1px solid #E3E8EF;border-radius:10px;border-spacing:0;
                  margin:0 0 24px 0;overflow:hidden;">
      <tr>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#0D1117;">Essentials</td>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;
                   font-size:14px;color:#0052CC;font-weight:700;text-align:right;">€49/mo</td>
      </tr>
      <tr>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   background:#F7F8FA;font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#0D1117;">
          Compliance <span style="font-size:9px;background:#0052CC;color:white;
                                  padding:2px 6px;border-radius:4px;margin-left:4px;
                                  font-weight:700;letter-spacing:0.05em;">POPULAR</span>
        </td>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;background:#F7F8FA;
                   font-family:-apple-system,sans-serif;
                   font-size:14px;color:#0052CC;font-weight:700;text-align:right;">€99/mo</td>
      </tr>
      <tr>
        <td class="table-cell" style="padding:13px 16px;font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#0D1117;">Business</td>
        <td class="table-cell" style="padding:13px 16px;font-family:-apple-system,sans-serif;
                   font-size:14px;color:#0052CC;font-weight:700;text-align:right;">€249/mo</td>
      </tr>
    </table>

    ${btn('Choose a plan →', `${APP_URL}/pricing`)}
    ${pSmall('Save 20% with annual billing. No lock-in — cancel anytime.')}
  `);
}

function trialEndingTomorrow(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${alertBanner('⚠️ Your trial ends in 24 hours', 'danger')}

    ${h1('Last chance to keep your protection.')}
    ${p(`Hi ${name}, tomorrow your AI Shield trial expires. Without a payment method, your team will lose access to:`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#FFF5F5;border:1px solid #FECACA;border-radius:10px;
                  border-spacing:0;margin:0 0 24px 0;">
      <tr><td class="info-block" style="padding:14px 18px;">
        <div class="body-text" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                    font-size:13px;color:#3A4250;line-height:1.9;">
          <span style="color:#D92D20;font-weight:800;margin-right:8px;">×</span>Real-time AI tool monitoring<br>
          <span style="color:#D92D20;font-weight:800;margin-right:8px;">×</span>Sensitive data blocking<br>
          <span style="color:#D92D20;font-weight:800;margin-right:8px;">×</span>Compliance reports & audit trail<br>
          <span style="color:#D92D20;font-weight:800;margin-right:8px;">×</span>Detection history & dashboards
        </div>
      </td></tr>
    </table>

    ${p('Add a payment method now and you won\'t be charged until your trial ends. <strong style="color:#0D1117;">Cancel anytime, no questions asked.</strong>')}

    ${btn('Keep My Protection Active →', `${APP_URL}/dashboard.html#billing`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#F7F8FA;border-left:3px solid #0052CC;border-radius:0 8px 8px 0;
                  border-spacing:0;margin:24px 0 0 0;">
      <tr><td class="info-block" style="padding:16px 18px;">
        <p class="quote-text" style="margin:0 0 8px 0;font-family:-apple-system,sans-serif;
                  font-size:13px;line-height:1.6;color:#3A4250;font-style:italic;">
          "We rolled it out to 18 people in an afternoon. The first week it caught three employees pasting client contract data into ChatGPT. <strong style="color:#0D1117;">It paid for itself immediately.</strong>"
        </p>
        <p style="margin:0;font-family:-apple-system,sans-serif;
                  font-size:11px;color:#6B7280;font-weight:600;">
          — Markus K., DPO · SaaS company, Munich
        </p>
      </td></tr>
    </table>

    ${pSmall(`Need more time? <a href="mailto:hello@getaishield.co" style="color:#0052CC;">Email us</a> — we can extend your trial.`)}
  `);
}

function trialExpired(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${h1('Your trial has ended.')}
    ${p(`Hi ${name}, your 14-day AI Shield trial has expired.`)}
    ${p(`AI Shield is no longer monitoring your team's AI tool usage. Your data is still safe — we haven't deleted anything. Upgrade to reactivate protection immediately.`)}

    ${btn('Reactivate now →', `${APP_URL}/pricing`)}
    ${pSmall('Questions? Reply to this email and we\'ll help.')}
  `);
}

function trialReactivation(nameOrEmail, stats = {}) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const { totalDetections = 0, totalBlocked = 0, finesMitigated = 0 } = stats;

  return wrap(`
    ${h1('Your protection is paused.')}
    ${p(`Hi ${name}, your 14-day trial has ended. Your team's AI activity is <strong style="color:#0D1117;">no longer being monitored</strong>. Here's what you accomplished during the trial:`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           class="stat-row"
           style="border-spacing:6px;border-collapse:separate;margin:0 -6px 24px -6px;">
      <tr>
        ${statCard(totalDetections, 'Detections', '#0052CC')}
        ${statCard(totalBlocked, 'Leaks blocked', '#059669')}
        ${statCard(`€${finesMitigated.toLocaleString()}`, 'Fines mitigated', '#0D1117')}
      </tr>
    </table>

    ${p('Don\'t lose this protection. <strong style="color:#0D1117;">Resubscribe in under 60 seconds</strong> — your data, settings and team configuration are all preserved.')}

    ${btn('Reactivate Protection →', `${APP_URL}/pricing`)}

    <div class="info-block" style="margin-top:24px;padding:14px 18px;background:#F7F8FA;border-radius:8px;">
      <p class="body-text" style="margin:0;font-family:-apple-system,sans-serif;
                font-size:13px;color:#3A4250;line-height:1.7;">
        <strong style="color:#0D1117;">Why teams resubscribe:</strong><br>
        🛡️ GDPR fines start at €20M — your subscription is a fraction of that risk<br>
        📊 The audit trail you built can't easily be rebuilt<br>
        ⏱️ EU AI Act enforcement: August 2026 — get controls in place now
      </p>
    </div>
  `);
}

function paymentConfirmed(nameOrEmail, plan, cycle) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  const planLabel = plan.charAt(0).toUpperCase() + plan.slice(1);
  const cycleLabel = cycle === 'annual' ? 'Annual (20% off)' : 'Monthly';

  return wrap(`
    ${h1(`✅ ${planLabel} plan is active.`)}
    ${p(`Hi ${name}, your AI Shield subscription is confirmed.`)}

    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="background:#F7F8FA;border-radius:10px;border-spacing:0;margin:0 0 24px 0;">
      <tr>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;font-size:13px;color:#6B7280;">Plan</td>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#0D1117;text-align:right;">${planLabel}</td>
      </tr>
      <tr>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;font-size:13px;color:#6B7280;">Billing</td>
        <td class="table-cell" style="padding:13px 16px;border-bottom:1px solid #E3E8EF;
                   font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#0D1117;text-align:right;">${cycleLabel}</td>
      </tr>
      <tr>
        <td class="table-cell" style="padding:13px 16px;font-family:-apple-system,sans-serif;
                   font-size:13px;color:#6B7280;">Status</td>
        <td class="table-cell" style="padding:13px 16px;font-family:-apple-system,sans-serif;
                   font-size:14px;font-weight:600;color:#059669;text-align:right;">Active ✓</td>
      </tr>
    </table>

    ${p('Your team is fully protected. GDPR audit reports are available in your dashboard anytime.')}

    ${btn('Open Dashboard →', `${APP_URL}/dashboard.html`)}
    ${pSmall(`To manage your subscription, update your card, or cancel — <a href="${APP_URL}/dashboard.html#billing" style="color:#0052CC;">visit billing settings</a>.`)}
  `);
}

function paymentFailed(nameOrEmail) {
  const name = nameOrEmail.includes('@') ? nameOrEmail.split('@')[0] : nameOrEmail;
  return wrap(`
    ${alertBanner('⚠️ Payment failed — action required', 'danger')}

    ${h1('We couldn\'t process your payment.')}
    ${p(`Hi ${name}, your AI Shield payment didn't go through.`)}
    ${p(`Your subscription is currently on hold. Please update your payment method to reactivate protection for your team.`)}

    ${btn('Update payment method →', `${APP_URL}/dashboard.html#billing`)}
    ${pSmall('We\'ll retry the payment automatically. If it fails again, your subscription will be cancelled.')}
  `);
}

module.exports = {
  welcome,
  employeeWelcome,
  trialDay7Checkin,
  trialAddPayment,
  trialEnding,
  trialEndingTomorrow,
  trialExpired,
  trialReactivation,
  paymentConfirmed,
  paymentFailed,
};
