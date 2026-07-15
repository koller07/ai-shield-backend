// ================================================================
// emails/monthly-reports.js
// Monthly compliance reports — branded with AI Shield identity
//
// 1. managerMonthlyReport() → manager view (full company report)
// 2. employeeMonthlySummary() → employee view (personal summary only)
// ================================================================

const LOGO_URL = 'https://www.getaishield.co/logo_full.png';
const APP_URL  = 'https://getaishield.co';

// ──────────────────────────────────────────────────────────
// MANAGER MONTHLY REPORT
// ──────────────────────────────────────────────────────────
function managerMonthlyReport(managerName, companyName, month, stats) {
  const {
    totalDetections   = 0,
    totalBlocked      = 0,
    activeEmployees   = 0,
    topDataTypes      = [],
    byEmployee        = [],
    topPlatforms      = [],
    previousDetections = null,
  } = stats;

  const monthLabel  = formatMonth(month);
  const blockRate   = totalDetections > 0
    ? Math.round((totalBlocked / totalDetections) * 100)
    : 0;

  // Thousands separator helper
  const fmtNum = (n) => Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');

  // ── Trend vs previous month (shown only if previousDetections is provided) ──
  let trendBlock = '';
  if (typeof previousDetections === 'number' && previousDetections >= 0) {
    const diff = totalDetections - previousDetections;
    if (diff === 0) {
      trendBlock = `
    <div style="background:#F7F8FA;border-radius:8px;padding:11px 16px;margin:0 0 24px 0;
                font-family:-apple-system,sans-serif;font-size:13px;color:#6B7280;">
      No change from last month (${previousDetections} detection${previousDetections !== 1 ? 's' : ''}).
    </div>`;
    } else {
      const down    = diff < 0;
      const pct     = previousDetections > 0 ? Math.round(Math.abs(diff) / previousDetections * 100) : null;
      const color   = down ? '#059669' : '#D97706';
      const bg      = down ? '#ECFDF5' : '#FFFBEB';
      const arrow   = down ? '&#9660;' : '&#9650;';
      const word    = down ? 'fewer' : 'more';
      const measure = pct !== null ? `${pct}% ${word}` : `${Math.abs(diff)} ${word}`;
      trendBlock = `
    <div style="background:${bg};border-radius:8px;padding:11px 16px;margin:0 0 24px 0;
                font-family:-apple-system,sans-serif;font-size:13px;color:#0D1117;">
      <span style="color:${color};font-weight:700;">${arrow} ${measure}</span>
      than last month (was ${previousDetections}).
    </div>`;
    }
  }

  // ── Estimated exposure mitigated (illustrative, not a guarantee) ──
  const AVG_INCIDENT_VALUE = 5000; // illustrative average cost per prevented incident
  const exposureMitigated  = totalBlocked * AVG_INCIDENT_VALUE;
  const exposureBlock = totalBlocked > 0 ? `
    <div style="background:#ECFDF5;border:1px solid rgba(5,150,105,0.25);
                border-radius:10px;padding:18px 20px;margin:0 0 28px 0;">
      <div style="font-family:-apple-system,sans-serif;font-size:11px;font-weight:700;
                  color:#059669;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">
        Estimated exposure mitigated
      </div>
      <div style="font-family:'Syne',-apple-system,sans-serif;font-size:30px;font-weight:800;
                  color:#059669;line-height:1;letter-spacing:-0.02em;">
        &euro;${fmtNum(exposureMitigated)}
      </div>
      <p style="font-family:-apple-system,sans-serif;font-size:11.5px;color:#6B7280;
                margin:10px 0 0 0;line-height:1.5;">
        Illustrative estimate: ${totalBlocked} blocked exposure${totalBlocked !== 1 ? 's' : ''}
        &times; &euro;${fmtNum(AVG_INCIDENT_VALUE)} average cost per prevented incident.
        Actual GDPR penalties can reach &euro;20M or 4% of global annual turnover.
      </p>
    </div>` : '';

  // Top data types rows
  const typeRows = topDataTypes.slice(0, 5).map((t, i) => `
    <tr style="background:${i % 2 === 0 ? '#F7F8FA' : '#ffffff'};">
      <td style="padding:11px 16px;font-family:-apple-system,sans-serif;
                 font-size:13px;color:#0D1117;font-weight:500;">${t.data_type}</td>
      <td style="padding:11px 16px;font-family:-apple-system,sans-serif;
                 font-size:13px;color:#0052CC;font-weight:700;text-align:right;">${t.count}</td>
    </tr>
  `).join('');

  // Employee rows
  const empRows = [...byEmployee]
    .sort((a, b) => b.count - a.count)
    .map((e, i) => `
    <tr style="background:${i % 2 === 0 ? '#F7F8FA' : '#ffffff'};">
      <td style="padding:11px 16px;font-family:-apple-system,sans-serif;
                 font-size:13px;color:#0D1117;">${e.employee_name || '—'}</td>
      <td style="padding:11px 16px;font-family:-apple-system,sans-serif;
                 font-size:13px;color:#6B7280;">${e.employee_email}</td>
      <td style="padding:11px 16px;font-family:-apple-system,sans-serif;
                 font-size:13px;font-weight:700;color:#D92D20;text-align:right;">${e.count}</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  body { margin: 0; padding: 0; background: #F7F8FA; }
  a { color: #0052CC; }
  @media only screen and (max-width: 600px) {
    .report-container { padding: 24px 20px !important; }
    .stat-cell { display: block !important; width: 100% !important; margin-bottom: 8px; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#F7F8FA;
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
       style="background:#F7F8FA;padding:32px 16px;">
<tr><td align="center">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600"
       style="max-width:600px;background:#ffffff;border-radius:14px;
              box-shadow:0 2px 8px rgba(0,0,0,0.04);overflow:hidden;">

  <!-- Branded header -->
  <tr><td style="background:#0D1117;padding:28px 32px;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
      <tr>
        <td>
          <img src="${LOGO_URL}" alt="AI Shield"
               style="height:28px;display:block;border:0;
                      filter:brightness(0) invert(1);" />
        </td>
        <td style="text-align:right;vertical-align:middle;">
          <span style="font-family:-apple-system,sans-serif;
                       font-size:11px;color:rgba(255,255,255,0.5);
                       text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">
            Monthly Report
          </span>
        </td>
      </tr>
    </table>
    <p style="font-family:-apple-system,sans-serif;
              color:rgba(255,255,255,0.6);font-size:13px;margin:12px 0 0 0;">
      ${monthLabel} compliance report
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td class="report-container" style="padding:32px;">

    <h1 style="font-family:'Syne',-apple-system,sans-serif;
               font-size:22px;font-weight:800;color:#0D1117;
               margin:0 0 6px 0;letter-spacing:-0.02em;">
      ${companyName} — ${monthLabel}
    </h1>
    <p style="font-family:-apple-system,sans-serif;
              color:#6B7280;font-size:14px;margin:0 0 28px 0;line-height:1.6;">
      Hi ${managerName}, here is your full AI Shield compliance report for ${monthLabel}.
    </p>

    <!-- Summary stats -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="border-spacing:8px;border-collapse:separate;margin:0 -8px 24px -8px;">
      <tr>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:18px;
                   text-align:center;width:33%;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:32px;font-weight:800;color:#D92D20;line-height:1;
                      letter-spacing:-0.02em;">${totalDetections}</div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:6px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">
            Total detections
          </div>
        </td>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:18px;
                   text-align:center;width:33%;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:32px;font-weight:800;color:#059669;line-height:1;
                      letter-spacing:-0.02em;">${totalBlocked}</div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:6px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">
            Blocked
          </div>
        </td>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:18px;
                   text-align:center;width:33%;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:32px;font-weight:800;color:#0052CC;line-height:1;
                      letter-spacing:-0.02em;">${activeEmployees}</div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:6px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">
            Active employees
          </div>
        </td>
      </tr>
    </table>
${trendBlock}
    <!-- Block rate bar -->
    <div style="margin-bottom:28px;">
      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
             style="margin-bottom:6px;">
        <tr>
          <td style="font-family:-apple-system,sans-serif;
                     font-size:12px;font-weight:600;color:#0D1117;">Block rate</td>
          <td style="text-align:right;font-family:-apple-system,sans-serif;
                     font-size:12px;font-weight:700;color:#059669;">${blockRate}%</td>
        </tr>
      </table>
      <div style="height:8px;background:#E3E8EF;border-radius:100px;overflow:hidden;">
        <div style="height:100%;width:${blockRate}%;background:#059669;border-radius:100px;"></div>
      </div>
    </div>
${exposureBlock}

    ${topDataTypes.length > 0 ? `
    <!-- Top data types -->
    <h3 style="font-family:'Syne',-apple-system,sans-serif;
               font-size:13px;font-weight:700;color:#0D1117;margin:0 0 10px 0;
               text-transform:uppercase;letter-spacing:0.07em;">Most detected data types</h3>
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="border-collapse:collapse;margin:0 0 28px 0;
                  border-radius:10px;overflow:hidden;border:1px solid #E3E8EF;">
      <thead>
        <tr style="background:#0052CC;">
          <th style="padding:11px 16px;font-family:-apple-system,sans-serif;
                     font-size:11px;color:white;text-align:left;font-weight:600;
                     letter-spacing:0.06em;text-transform:uppercase;">Type</th>
          <th style="padding:11px 16px;font-family:-apple-system,sans-serif;
                     font-size:11px;color:white;text-align:right;font-weight:600;
                     letter-spacing:0.06em;text-transform:uppercase;">Detections</th>
        </tr>
      </thead>
      <tbody>${typeRows}</tbody>
    </table>` : ''}

    ${byEmployee.length > 0 ? `
    <!-- By employee -->
    <h3 style="font-family:'Syne',-apple-system,sans-serif;
               font-size:13px;font-weight:700;color:#0D1117;margin:0 0 10px 0;
               text-transform:uppercase;letter-spacing:0.07em;">Detections by employee</h3>
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="border-collapse:collapse;margin:0 0 28px 0;
                  border-radius:10px;overflow:hidden;border:1px solid #E3E8EF;">
      <thead>
        <tr style="background:#0052CC;">
          <th style="padding:11px 16px;font-family:-apple-system,sans-serif;
                     font-size:11px;color:white;text-align:left;font-weight:600;
                     letter-spacing:0.06em;text-transform:uppercase;">Name</th>
          <th style="padding:11px 16px;font-family:-apple-system,sans-serif;
                     font-size:11px;color:white;text-align:left;font-weight:600;
                     letter-spacing:0.06em;text-transform:uppercase;">Email</th>
          <th style="padding:11px 16px;font-family:-apple-system,sans-serif;
                     font-size:11px;color:white;text-align:right;font-weight:600;
                     letter-spacing:0.06em;text-transform:uppercase;">Detections</th>
        </tr>
      </thead>
      <tbody>${empRows}</tbody>
    </table>` : ''}

    <!-- CTA -->
    <p style="font-family:-apple-system,sans-serif;font-size:14px;color:#0D1117;
              margin:0 0 12px 0;line-height:1.6;font-weight:600;">
      Review every detection and keep your audit trail ready for your DPO.
    </p>
    <table role="presentation" cellspacing="0" cellpadding="0" border="0"
           style="margin:0 0 28px 0;">
      <tr><td style="border-radius:8px;background:#0052CC;">
        <a href="${APP_URL}/dashboard"
           style="display:inline-block;background:#0052CC;color:#ffffff;
                  font-family:-apple-system,sans-serif;
                  font-weight:600;font-size:14px;padding:13px 26px;
                  border-radius:8px;text-decoration:none;
                  border:1px solid #0052CC;">
          Review the full audit trail →
        </a>
      </td></tr>
    </table>

    <!-- GDPR note -->
    <div style="background:#FFFBEB;border:1px solid rgba(245,158,11,0.25);
                border-radius:8px;padding:14px 16px;">
      <p style="font-family:-apple-system,sans-serif;
                font-size:12px;color:#92400E;margin:0;line-height:1.6;">
        <strong>GDPR Art. 32 note:</strong> This report documents the technical measures
        in place to prevent unauthorised disclosure of personal data via AI tools.
        It can be presented to your DPA as evidence of compliance.
        <a href="${APP_URL}/dashboard" style="color:#0052CC;font-weight:600;">
          Export full audit report →
        </a>
      </p>
    </div>

  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:20px 32px;border-top:1px solid #E3E8EF;background:#F7F8FA;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
      <tr>
        <td style="vertical-align:middle;">
          <p style="font-family:-apple-system,sans-serif;
                    color:#9CA3AF;font-size:12px;margin:0;line-height:1.5;">
            <strong style="color:#6B7280;">AI Shield</strong> by Koller Group<br>
            <a href="${APP_URL}" style="color:#9CA3AF;text-decoration:none;">getaishield.co</a>
            · Auto-generated on the 1st of each month
          </p>
        </td>
        <td style="text-align:right;vertical-align:middle;">
          <img src="${LOGO_URL}" alt="AI Shield"
               style="height:18px;opacity:0.4;display:inline-block;border:0;" />
        </td>
      </tr>
    </table>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────
// EMPLOYEE MONTHLY SUMMARY (personal — no colleagues data)
// ──────────────────────────────────────────────────────────
function employeeMonthlySummary(employeeName, companyName, month, stats) {
  const {
    totalDetections = 0,
    totalBlocked    = 0,
    topDataType     = null,
    topPlatform     = null,
  } = stats;

  const monthLabel = formatMonth(month);
  const name = employeeName?.split(' ')[0] || 'there';

  const riskLevel = totalDetections === 0 ? 'none'
    : totalDetections <= 3  ? 'low'
    : totalDetections <= 10 ? 'medium'
    : 'high';

  const riskConfig = {
    none:   { label: 'No detections', color: '#059669', bg: '#ECFDF5', border: 'rgba(5,150,105,0.2)',  message: 'Great work — no sensitive data was detected in your AI prompts this month.' },
    low:    { label: 'Low',           color: '#059669', bg: '#ECFDF5', border: 'rgba(5,150,105,0.2)',  message: `Only ${totalDetections} detection${totalDetections !== 1 ? 's' : ''} this month. You're doing well at keeping sensitive data out of AI tools.` },
    medium: { label: 'Medium',        color: '#D97706', bg: '#FFFBEB', border: 'rgba(245,158,11,0.25)', message: `${totalDetections} detections this month. AI Shield blocked ${totalBlocked} of them. Review the tips below to reduce this further.` },
    high:   { label: 'High',          color: '#D92D20', bg: '#FFF1F0', border: 'rgba(217,45,32,0.2)',  message: `${totalDetections} detections this month — this is higher than usual. ${totalBlocked} were blocked. Please review what types of data you're sharing with AI tools.` },
  }[riskLevel];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  body { margin: 0; padding: 0; background: #F7F8FA; }
  a { color: #0052CC; }
  @media only screen and (max-width: 600px) {
    .summary-container { padding: 24px 20px !important; }
    .stat-cell { display: block !important; width: 100% !important; margin-bottom: 8px; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#F7F8FA;
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
       style="background:#F7F8FA;padding:32px 16px;">
<tr><td align="center">

<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="560"
       style="max-width:560px;background:#ffffff;border-radius:14px;
              box-shadow:0 2px 8px rgba(0,0,0,0.04);overflow:hidden;">

  <!-- Branded header -->
  <tr><td style="background:#0D1117;padding:24px 28px;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
      <tr>
        <td>
          <img src="${LOGO_URL}" alt="AI Shield"
               style="height:24px;display:block;border:0;
                      filter:brightness(0) invert(1);" />
        </td>
        <td style="text-align:right;vertical-align:middle;">
          <span style="font-family:-apple-system,sans-serif;
                       font-size:11px;color:rgba(255,255,255,0.5);
                       text-transform:uppercase;letter-spacing:0.08em;font-weight:600;">
            Personal Summary
          </span>
        </td>
      </tr>
    </table>
    <p style="font-family:-apple-system,sans-serif;
              color:rgba(255,255,255,0.6);font-size:12px;margin:8px 0 0 0;">
      ${monthLabel}
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td class="summary-container" style="padding:28px;">

    <h1 style="font-family:'Syne',-apple-system,sans-serif;
               font-size:20px;font-weight:800;color:#0D1117;
               margin:0 0 8px 0;letter-spacing:-0.02em;">
      Hi ${name}, here's your ${monthLabel} summary.
    </h1>
    <p style="font-family:-apple-system,sans-serif;
              color:#6B7280;font-size:14px;margin:0 0 24px 0;line-height:1.6;">
      Personal summary of what AI Shield detected in your browser this month at ${companyName}.
      Only you and your account manager can see this data.
    </p>

    <!-- Risk level banner -->
    <div style="background:${riskConfig.bg};border:1px solid ${riskConfig.border};
                border-radius:10px;padding:16px 18px;margin:0 0 24px 0;">
      <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-bottom:8px;">
        <tr>
          <td style="font-family:-apple-system,sans-serif;
                     font-size:11px;font-weight:700;text-transform:uppercase;
                     letter-spacing:0.09em;color:${riskConfig.color};
                     padding-right:10px;">Detection level</td>
          <td>
            <span style="background:${riskConfig.color};color:white;
                         font-family:-apple-system,sans-serif;
                         font-size:11px;font-weight:700;padding:3px 9px;
                         border-radius:100px;">
              ${riskConfig.label}
            </span>
          </td>
        </tr>
      </table>
      <p style="font-family:-apple-system,sans-serif;
                font-size:13px;color:#0D1117;margin:0;line-height:1.6;">
        ${riskConfig.message}
      </p>
    </div>

    <!-- Stats -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%"
           style="border-spacing:8px;border-collapse:separate;margin:0 -8px 24px -8px;">
      <tr>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:28px;font-weight:800;color:#D92D20;line-height:1;
                      letter-spacing:-0.02em;">${totalDetections}</div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:5px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">Detections</div>
        </td>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:28px;font-weight:800;color:#059669;line-height:1;
                      letter-spacing:-0.02em;">${totalBlocked}</div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:5px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">Blocked</div>
        </td>
        <td class="stat-cell"
            style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center;">
          <div style="font-family:'Syne',-apple-system,sans-serif;
                      font-size:22px;font-weight:800;color:#0052CC;line-height:1;
                      letter-spacing:-0.02em;">
            ${topDataType ? topDataType.data_type : '—'}
          </div>
          <div style="font-family:-apple-system,sans-serif;
                      font-size:11px;color:#9CA3AF;margin-top:5px;
                      text-transform:uppercase;letter-spacing:0.07em;font-weight:600;">Most detected</div>
        </td>
      </tr>
    </table>

    ${topDataType ? `
    <!-- Data type explanation -->
    <div style="background:#F7F8FA;border-radius:10px;padding:16px 18px;margin:0 0 24px 0;">
      <p style="font-family:-apple-system,sans-serif;
                font-size:12px;font-weight:700;color:#0D1117;margin:0 0 8px 0;
                text-transform:uppercase;letter-spacing:0.07em;">
        Most frequently detected: ${topDataType.data_type}
      </p>
      <p style="font-family:-apple-system,sans-serif;
                font-size:13px;color:#6B7280;margin:0;line-height:1.6;">
        ${dataTypeExplanation(topDataType.data_type)}
      </p>
    </div>` : ''}

    <!-- Tips -->
    <div style="border:1px solid #E3E8EF;border-radius:10px;padding:16px 18px;margin:0 0 24px 0;">
      <p style="font-family:'Syne',-apple-system,sans-serif;
                font-size:12px;font-weight:700;color:#0D1117;margin:0 0 12px 0;
                text-transform:uppercase;letter-spacing:0.07em;">
        Quick tips to stay safe
      </p>
      <ul style="margin:0;padding-left:18px;color:#6B7280;
                 font-family:-apple-system,sans-serif;
                 font-size:13px;line-height:2;">
        <li>Never paste client financial details directly into AI prompts</li>
        <li>Use placeholders: <span style="font-family:Menlo,Monaco,monospace;font-size:12px;background:#EEF1F5;padding:1px 6px;border-radius:3px;">"IBAN: [CLIENT_IBAN]"</span> instead of the real number</li>
        <li>When AI Shield alerts you, always click <strong style="color:#0D1117;">"Remove data"</strong> before sending</li>
        <li>When in doubt, ask your manager before sharing sensitive documents with AI</li>
      </ul>
    </div>

    <p style="font-family:-apple-system,sans-serif;
              color:#9CA3AF;font-size:12px;margin:0;line-height:1.6;">
      This email is sent automatically on the 1st of each month.
      Your personal data is never shared with third parties.
      Questions? Contact <a href="mailto:hello@getaishield.co" style="color:#0052CC;">hello@getaishield.co</a>
    </p>

  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:18px 28px;border-top:1px solid #E3E8EF;background:#F7F8FA;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
      <tr>
        <td style="vertical-align:middle;">
          <p style="font-family:-apple-system,sans-serif;
                    color:#9CA3AF;font-size:12px;margin:0;">
            <strong style="color:#6B7280;">AI Shield</strong> ·
            <a href="${APP_URL}" style="color:#9CA3AF;text-decoration:none;">getaishield.co</a>
          </p>
        </td>
        <td style="text-align:right;vertical-align:middle;">
          <img src="${LOGO_URL}" alt="AI Shield"
               style="height:16px;opacity:0.4;display:inline-block;border:0;" />
        </td>
      </tr>
    </table>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

// ─── Helpers ─────────────────────────────────────────────
function formatMonth(monthStr) {
  const [year, month] = monthStr.split('-');
  const names = ['January','February','March','April','May','June',
                 'July','August','September','October','November','December'];
  return `${names[parseInt(month, 10) - 1]} ${year}`;
}

function dataTypeExplanation(type) {
  const explanations = {
    IBAN:        'Bank account numbers (IBANs) are sensitive financial data. Sharing them with AI tools violates GDPR and may expose your clients to fraud.',
    CREDIT_CARD: 'Credit card numbers are PCI DSS protected. Never paste them into AI tools — use masked versions (e.g. **** **** **** 1234) instead.',
    EMAIL:       'Customer or employee email addresses are personal data under GDPR. Use anonymised examples in AI prompts.',
    CPF:         'CPF numbers are personal identifiers. Treat them like passport numbers — never share in AI tools.',
    CNPJ:        'CNPJ numbers can identify companies and their tax situation. Avoid sharing in AI prompts.',
    NIF:         'Tax identification numbers (NIFs) are sensitive personal data under GDPR.',
    PHONE:       'Phone numbers are personal data. Use placeholder formats like +XX XXX XXX XXX in AI prompts.',
    API_KEY:     'API keys and tokens give access to systems. Sharing them in AI tools can lead to security breaches.',
    PASSWORD:    'Passwords should never be shared anywhere — especially not in AI tools.',
  };
  return explanations[type] || 'This type of data is protected under GDPR and should not be shared with AI tools.';
}

module.exports = { managerMonthlyReport, employeeMonthlySummary };
