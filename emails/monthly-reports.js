// ================================================================
// emails/monthly-reports.js
// Templates para os relatórios mensais automáticos
//
// 1. managerMonthlyReport() → enviado ao manager no início do mês
//    com o relatório completo da empresa (todos os funcionários)
//
// 2. employeeMonthlySummary() → enviado a cada funcionário
//    com o seu resumo pessoal (total + tipo mais frequente)
// ================================================================

function managerMonthlyReport(managerName, companyName, month, stats) {
  const {
    totalDetections   = 0,
    totalBlocked      = 0,
    activeEmployees   = 0,
    topDataTypes      = [],   // [{ data_type, count }]
    byEmployee        = [],   // [{ employee_name, employee_email, count }]
    topPlatforms      = [],   // [{ platform, count }]
  } = stats;

  const monthLabel  = formatMonth(month);
  const blockRate   = totalDetections > 0
    ? Math.round((totalBlocked / totalDetections) * 100)
    : 0;

  // Build top data types rows
  const typeRows = topDataTypes.slice(0, 5).map((t, i) => `
    <tr style="background:${i % 2 === 0 ? '#F7F8FA' : '#ffffff'}">
      <td style="padding:10px 16px;font-size:13px;color:#0D1117;font-weight:500">${t.data_type}</td>
      <td style="padding:10px 16px;font-size:13px;color:#0052CC;font-weight:700;text-align:right">${t.count}</td>
    </tr>
  `).join('');

  // Build employee rows (sorted by count desc)
  const empRows = [...byEmployee]
    .sort((a, b) => b.count - a.count)
    .map((e, i) => `
    <tr style="background:${i % 2 === 0 ? '#F7F8FA' : '#ffffff'}">
      <td style="padding:10px 16px;font-size:13px;color:#0D1117">${e.employee_name || '—'}</td>
      <td style="padding:10px 16px;font-size:13px;color:#6B7280">${e.employee_email}</td>
      <td style="padding:10px 16px;font-size:13px;font-weight:700;color:#D92D20;text-align:right">${e.count}</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>
  <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
              max-width:600px;margin:0 auto;padding:0;background:#ffffff">

    <!-- Header -->
    <div style="background:#0D1117;padding:28px 32px;border-radius:12px 12px 0 0">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
        <div style="width:32px;height:32px;background:#0052CC;border-radius:8px;
                    display:flex;align-items:center;justify-content:center">
          <span style="color:white;font-size:16px">🛡️</span>
        </div>
        <span style="font-size:18px;font-weight:800;color:white">AI Shield</span>
      </div>
      <p style="color:rgba(255,255,255,.5);font-size:13px;margin:6px 0 0">
        Monthly Compliance Report — ${monthLabel}
      </p>
    </div>

    <!-- Body -->
    <div style="padding:32px">
      <h1 style="font-size:20px;font-weight:800;color:#0D1117;margin:0 0 6px">
        ${companyName} — ${monthLabel} Report
      </h1>
      <p style="color:#6B7280;font-size:14px;margin:0 0 28px">
        Hi ${managerName}, here is your full AI Shield compliance report for ${monthLabel}.
      </p>

      <!-- Summary cards -->
      <table style="width:100%;border-spacing:8px;border-collapse:separate;margin-bottom:24px">
        <tr>
          <td style="background:#F7F8FA;border-radius:10px;padding:18px;text-align:center;width:33%">
            <div style="font-size:32px;font-weight:800;color:#D92D20;line-height:1">${totalDetections}</div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:5px;text-transform:uppercase;letter-spacing:.07em">Total detections</div>
          </td>
          <td style="background:#F7F8FA;border-radius:10px;padding:18px;text-align:center;width:33%">
            <div style="font-size:32px;font-weight:800;color:#059669;line-height:1">${totalBlocked}</div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:5px;text-transform:uppercase;letter-spacing:.07em">Blocked</div>
          </td>
          <td style="background:#F7F8FA;border-radius:10px;padding:18px;text-align:center;width:33%">
            <div style="font-size:32px;font-weight:800;color:#0052CC;line-height:1">${activeEmployees}</div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:5px;text-transform:uppercase;letter-spacing:.07em">Active employees</div>
          </td>
        </tr>
      </table>

      <!-- Block rate bar -->
      <div style="margin-bottom:28px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:12px;font-weight:600;color:#0D1117">Block rate</span>
          <span style="font-size:12px;font-weight:700;color:#059669">${blockRate}%</span>
        </div>
        <div style="height:7px;background:#E3E8EF;border-radius:100px;overflow:hidden">
          <div style="height:100%;width:${blockRate}%;background:#059669;border-radius:100px"></div>
        </div>
      </div>

      <!-- Top data types -->
      ${topDataTypes.length > 0 ? `
      <h3 style="font-size:13px;font-weight:700;color:#0D1117;margin:0 0 10px;
                 text-transform:uppercase;letter-spacing:.07em">Most detected data types</h3>
      <table style="width:100%;border-collapse:collapse;margin-bottom:28px;
                    border-radius:10px;overflow:hidden;border:1px solid #E3E8EF">
        <thead>
          <tr style="background:#0052CC">
            <th style="padding:10px 16px;font-size:11px;color:white;text-align:left;font-weight:600;letter-spacing:.06em">Type</th>
            <th style="padding:10px 16px;font-size:11px;color:white;text-align:right;font-weight:600;letter-spacing:.06em">Detections</th>
          </tr>
        </thead>
        <tbody>${typeRows}</tbody>
      </table>` : ''}

      <!-- By employee -->
      ${byEmployee.length > 0 ? `
      <h3 style="font-size:13px;font-weight:700;color:#0D1117;margin:0 0 10px;
                 text-transform:uppercase;letter-spacing:.07em">Detections by employee</h3>
      <table style="width:100%;border-collapse:collapse;margin-bottom:28px;
                    border-radius:10px;overflow:hidden;border:1px solid #E3E8EF">
        <thead>
          <tr style="background:#0052CC">
            <th style="padding:10px 16px;font-size:11px;color:white;text-align:left;font-weight:600">Name</th>
            <th style="padding:10px 16px;font-size:11px;color:white;text-align:left;font-weight:600">Email</th>
            <th style="padding:10px 16px;font-size:11px;color:white;text-align:right;font-weight:600">Detections</th>
          </tr>
        </thead>
        <tbody>${empRows}</tbody>
      </table>` : ''}

      <!-- CTA -->
      <a href="https://getaishield.co/dashboard.html"
         style="display:inline-block;background:#0052CC;color:white;font-weight:600;
                padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px;
                margin-bottom:28px">
        View full dashboard →
      </a>

      <!-- GDPR note -->
      <div style="background:#FFFBEB;border:1px solid rgba(245,158,11,.25);
                  border-radius:8px;padding:14px 16px;margin-bottom:0">
        <p style="font-size:12px;color:#92400E;margin:0;line-height:1.6">
          <strong>GDPR Art. 32 note:</strong> This report documents the technical measures
          in place to prevent unauthorised disclosure of personal data via AI tools.
          It can be presented to your DPA as evidence of compliance.
          <a href="https://getaishield.co/dashboard.html" style="color:#0052CC">
            Export full audit report →
          </a>
        </p>
      </div>
    </div>

    <!-- Footer -->
    <div style="padding:20px 32px;border-top:1px solid #E3E8EF">
      <p style="color:#9CA3AF;font-size:12px;margin:0">
        AI Shield · <a href="https://getaishield.co" style="color:#9CA3AF">getaishield.co</a>
        &nbsp;·&nbsp; This report is generated automatically on the 1st of each month.
      </p>
    </div>
  </div>
  </body></html>`;
}

// ──────────────────────────────────────────────────────────
// EMPLOYEE MONTHLY SUMMARY
// Sent to each employee — no data about colleagues
// ──────────────────────────────────────────────────────────
function employeeMonthlySummary(employeeName, companyName, month, stats) {
  const {
    totalDetections = 0,
    totalBlocked    = 0,
    topDataType     = null,   // { data_type, count } — the most frequent
    topPlatform     = null,   // { platform, count }
  } = stats;

  const monthLabel = formatMonth(month);
  const name = employeeName?.split(' ')[0] || 'there';

  const riskLevel = totalDetections === 0 ? 'none'
    : totalDetections <= 3  ? 'low'
    : totalDetections <= 10 ? 'medium'
    : 'high';

  const riskConfig = {
    none:   { label: 'No detections',  color: '#059669', bg: '#ECFDF5', border: 'rgba(5,150,105,.2)',  message: 'Great work — no sensitive data was detected in your AI prompts this month.' },
    low:    { label: 'Low',            color: '#059669', bg: '#ECFDF5', border: 'rgba(5,150,105,.2)',  message: `Only ${totalDetections} detection${totalDetections !== 1 ? 's' : ''} this month. You're doing well at keeping sensitive data out of AI tools.` },
    medium: { label: 'Medium',         color: '#D97706', bg: '#FFFBEB', border: 'rgba(245,158,11,.25)',message: `${totalDetections} detections this month. AI Shield blocked ${totalBlocked} of them. Review the tips below to reduce this further.` },
    high:   { label: 'High',           color: '#D92D20', bg: '#FFF1F0', border: 'rgba(217,45,32,.2)',  message: `${totalDetections} detections this month — this is higher than usual. ${totalBlocked} were blocked. Please review what types of data you're sharing with AI tools.` },
  }[riskLevel];

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>
  <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
              max-width:560px;margin:0 auto;padding:0;background:#ffffff">

    <!-- Header -->
    <div style="background:#0D1117;padding:24px 28px;border-radius:12px 12px 0 0">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:20px">🛡️</span>
        <div>
          <span style="font-size:16px;font-weight:800;color:white">AI Shield</span>
          <p style="color:rgba(255,255,255,.45);font-size:12px;margin:2px 0 0">
            Your monthly summary — ${monthLabel}
          </p>
        </div>
      </div>
    </div>

    <!-- Body -->
    <div style="padding:28px">
      <h1 style="font-size:19px;font-weight:800;color:#0D1117;margin:0 0 8px">
        Hi ${name}, here's your ${monthLabel} summary.
      </h1>
      <p style="color:#6B7280;font-size:14px;margin:0 0 24px;line-height:1.6">
        This is a personal summary of what AI Shield detected in your browser this month at ${companyName}.
        Only you and your account manager can see this data.
      </p>

      <!-- Risk level banner -->
      <div style="background:${riskConfig.bg};border:1px solid ${riskConfig.border};
                  border-radius:10px;padding:16px 18px;margin-bottom:24px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="font-size:11px;font-weight:700;text-transform:uppercase;
                       letter-spacing:.09em;color:${riskConfig.color}">Detection level</span>
          <span style="background:${riskConfig.color};color:white;font-size:11px;
                       font-weight:700;padding:2px 9px;border-radius:100px">
            ${riskConfig.label}
          </span>
        </div>
        <p style="font-size:13px;color:#0D1117;margin:0;line-height:1.6">${riskConfig.message}</p>
      </div>

      <!-- Stats -->
      <table style="width:100%;border-spacing:8px;border-collapse:separate;margin-bottom:24px">
        <tr>
          <td style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center">
            <div style="font-size:28px;font-weight:800;color:#D92D20;line-height:1">${totalDetections}</div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:4px">Detections</div>
          </td>
          <td style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center">
            <div style="font-size:28px;font-weight:800;color:#059669;line-height:1">${totalBlocked}</div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:4px">Blocked</div>
          </td>
          <td style="background:#F7F8FA;border-radius:10px;padding:16px;text-align:center">
            <div style="font-size:24px;font-weight:800;color:#0052CC;line-height:1">
              ${topDataType ? topDataType.data_type : '—'}
            </div>
            <div style="font-size:11px;color:#9CA3AF;margin-top:4px">Most detected type</div>
          </td>
        </tr>
      </table>

      ${topDataType ? `
      <!-- What was detected -->
      <div style="background:#F7F8FA;border-radius:10px;padding:16px 18px;margin-bottom:24px">
        <p style="font-size:12px;font-weight:700;color:#0D1117;margin:0 0 8px;
                  text-transform:uppercase;letter-spacing:.07em">
          Most frequently detected: ${topDataType.data_type}
        </p>
        <p style="font-size:13px;color:#6B7280;margin:0;line-height:1.6">
          ${dataTypeExplanation(topDataType.data_type)}
        </p>
      </div>` : ''}

      <!-- Tips -->
      <div style="border:1px solid #E3E8EF;border-radius:10px;padding:16px 18px;margin-bottom:24px">
        <p style="font-size:12px;font-weight:700;color:#0D1117;margin:0 0 10px;
                  text-transform:uppercase;letter-spacing:.07em">
          Quick tips to stay safe
        </p>
        <ul style="margin:0;padding-left:18px;color:#6B7280;font-size:13px;line-height:2">
          <li>Never paste client financial details directly into AI prompts</li>
          <li>Use placeholders: "IBAN: [CLIENT_IBAN]" instead of the real number</li>
          <li>When AI Shield alerts you, always click "Remove data" before sending</li>
          <li>When in doubt, ask your manager before sharing sensitive documents with AI</li>
        </ul>
      </div>

      <p style="color:#9CA3AF;font-size:12px;margin:0;line-height:1.6">
        This email is sent automatically on the 1st of each month.
        Your personal data is never shared with third parties.
        Questions? Contact <a href="mailto:hello@getaishield.co" style="color:#0052CC">hello@getaishield.co</a>
      </p>
    </div>

    <!-- Footer -->
    <div style="padding:16px 28px;border-top:1px solid #E3E8EF">
      <p style="color:#9CA3AF;font-size:12px;margin:0">
        AI Shield · <a href="https://getaishield.co" style="color:#9CA3AF">getaishield.co</a>
      </p>
    </div>
  </div>
  </body></html>`;
}

// ─── Helpers ─────────────────────────────────────────────
function formatMonth(monthStr) {
  // '2026-04' → 'April 2026'
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
