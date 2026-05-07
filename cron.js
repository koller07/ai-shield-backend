// ================================================================
// cron.js — v3
// Tarefas automáticas agendadas
//
// JOBS:
// 1. Trial Day 7 check-in       → 09:00 UTC diário
// 2. Trial Day 11 add payment   → 09:00 UTC diário
// 3. Trial Day 13 ending tomorrow → 09:00 UTC diário
// 4. Trial expiry check + reactivation → a cada hora
// 5. Manager monthly report     → dia 1 do mês, 08:00 UTC
// 6. Employee monthly summary   → dia 1 do mês, 09:00 UTC
// ================================================================

const cron   = require(‘node-cron’);
const { Pool } = require(‘pg’);
const { Resend } = require(‘resend’);
const emails = require(’./emails’);
const { managerMonthlyReport, employeeMonthlySummary } = require(’./emails/monthly-reports’);

const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = `AI Shield <hello@${process.env.EMAIL_DOMAIN || 'getaishield.co'}>`;

// ─── Helper: send email ───────────────────────────────────
async function send(to, subject, html) {
try {
await resend.emails.send({ from: FROM, to, subject, html });
console.log(`[CRON] Email sent: ${subject} → ${to}`);
} catch (err) {
console.error(`[CRON] Email failed to ${to}:`, err.message);
}
}

// ─── Helper: send once per type per user ──────────────────
// Prevents sending the same email twice within 20 hours
async function sendOnce(userId, type, to, subject, html) {
const { rows } = await pool.query(
`SELECT id FROM email_log WHERE user_id = $1 AND email_type = $2 AND sent_at > NOW() - INTERVAL '20 hours'`,
[userId, type]
);
if (rows.length) return;
await send(to, subject, html);
await pool.query(
‘INSERT INTO email_log (user_id, email_type) VALUES ($1, $2)’,
[userId, type]
);
}

// ─── Helper: get company stats for emails ─────────────────
async function getCompanyStats(companyId) {
try {
const { rows: totals } = await pool.query(`SELECT COUNT(*)                            AS total_detections, COUNT(*) FILTER (WHERE was_blocked) AS total_blocked FROM detections WHERE company_id = $1`, [companyId]);

```
const { rows: emp } = await pool.query(`
  SELECT COUNT(*) AS active_employees
  FROM users
  WHERE company_id = $1 AND role = 'employee' AND is_active = true
`, [companyId]);

return {
  totalDetections: parseInt(totals[0]?.total_detections) || 0,
  totalBlocked:    parseInt(totals[0]?.total_blocked)    || 0,
  activeEmployees: parseInt(emp[0]?.active_employees)    || 0,
};
```

} catch (err) {
console.error(’[CRON] getCompanyStats error:’, err.message);
return { totalDetections: 0, totalBlocked: 0, activeEmployees: 0 };
}
}

// ─── Helper: get previous month string ────────────────────
function prevMonth() {
const d = new Date();
d.setDate(1);
d.setMonth(d.getMonth() - 1);
return d.toISOString().slice(0, 7); // ‘YYYY-MM’
}

function formatMonthShort(monthStr) {
const [year, month] = monthStr.split(’-’);
const names = [‘Jan’,‘Feb’,‘Mar’,‘Apr’,‘May’,‘Jun’,
‘Jul’,‘Aug’,‘Sep’,‘Oct’,‘Nov’,‘Dec’];
return `${names[parseInt(month, 10) - 1]} ${year}`;
}

// ════════════════════════════════════════════════════════════
// JOB 1 — Trial Day 7 check-in (daily at 09:00 UTC)
// Sent to managers whose trial started ~7 days ago
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 9 * * *’, async () => {
console.log(’[CRON] Day 7 check-in — looking for trials…’);
try {
const { rows } = await pool.query(`SELECT u.id, u.email, u.name, s.company_id, s.created_at FROM subscriptions s JOIN users u ON u.id = s.created_by_user_id WHERE s.status = 'trialing' AND s.created_at::date = CURRENT_DATE - INTERVAL '7 days'`);

```
for (const row of rows) {
  const stats = await getCompanyStats(row.company_id);
  await sendOnce(
    row.id, 'trial_day7', row.email,
    "You're halfway through your AI Shield trial",
    emails.trialDay7Checkin(row.name || row.email, stats)
  );
}

if (rows.length > 0) console.log(`[CRON] Day 7 emails sent: ${rows.length}`);
```

} catch (err) {
console.error(’[CRON] trial_day7 error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// JOB 2 — Trial Day 11 add payment (daily at 09:00 UTC)
// Sent 3 days before trial expires
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 9 * * *’, async () => {
console.log(’[CRON] Day 11 add-payment — looking for trials…’);
try {
const { rows } = await pool.query(`SELECT u.id, u.email, u.name, s.plan, s.trial_ends_at FROM subscriptions s JOIN users u ON u.id = s.created_by_user_id WHERE s.status = 'trialing' AND s.stripe_subscription_id IS NULL AND s.trial_ends_at BETWEEN NOW() + INTERVAL '2 days 12 hours' AND NOW() + INTERVAL '3 days 12 hours'`);

```
for (const row of rows) {
  const days = Math.max(1, Math.ceil((new Date(row.trial_ends_at) - Date.now()) / 86400000));
  // Default to 'compliance' if plan is still 'trial' (no plan chosen yet)
  const plan = (row.plan && row.plan !== 'trial') ? row.plan : 'compliance';
  await sendOnce(
    row.id, 'trial_day11', row.email,
    `${days} days left — keep your AI Shield protection active`,
    emails.trialAddPayment(row.name || row.email, plan, days)
  );
}

if (rows.length > 0) console.log(`[CRON] Day 11 emails sent: ${rows.length}`);
```

} catch (err) {
console.error(’[CRON] trial_day11 error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// JOB 3 — Trial Day 13 ending tomorrow (daily at 09:00 UTC)
// Final 24h reminder
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 9 * * *’, async () => {
console.log(’[CRON] Day 13 ending-tomorrow — looking for trials…’);
try {
const { rows } = await pool.query(`SELECT u.id, u.email, u.name FROM subscriptions s JOIN users u ON u.id = s.created_by_user_id WHERE s.status = 'trialing' AND s.stripe_subscription_id IS NULL AND s.trial_ends_at BETWEEN NOW() + INTERVAL '12 hours' AND NOW() + INTERVAL '36 hours'`);

```
for (const row of rows) {
  await sendOnce(
    row.id, 'trial_day13', row.email,
    '⚠️ Your AI Shield trial ends tomorrow',
    emails.trialEndingTomorrow(row.name || row.email)
  );
}

if (rows.length > 0) console.log(`[CRON] Day 13 emails sent: ${rows.length}`);
```

} catch (err) {
console.error(’[CRON] trial_day13 error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// JOB 4 — Expire overdue trials (every hour)
// Marks subscriptions as ‘expired’ and sends reactivation email
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 * * * *’, async () => {
try {
// Find and mark expired
const { rows } = await pool.query(`UPDATE subscriptions SET status = 'expired', updated_at = NOW() WHERE status = 'trialing' AND trial_ends_at < NOW() AND stripe_subscription_id IS NULL RETURNING company_id, created_by_user_id AS user_id`);

```
if (rows.length === 0) return;

console.log(`[CRON] Expired ${rows.length} trial(s)`);

// Send reactivation email with stats
for (const row of rows) {
  const userResult = await pool.query(
    'SELECT email, name FROM users WHERE id = $1',
    [row.user_id]
  );
  const user = userResult.rows[0];
  if (!user) continue;

  const stats = await getCompanyStats(row.company_id);

  // Estimate fines mitigated based on detections
  // Conservative: €5,000 per blocked sensitive data leak
  const finesMitigated = stats.totalBlocked * 5000;

  await sendOnce(
    row.user_id, 'trial_expired', user.email,
    'Your AI Shield protection is paused — reactivate now',
    emails.trialReactivation(user.name || user.email, {
      ...stats,
      finesMitigated
    })
  );
}
```

} catch (err) {
console.error(’[CRON] expire_trials error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// JOB 5 — Manager monthly report (1st of month at 08:00 UTC)
// Full company report sent to managers
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 8 1 * *’, async () => {
const month = prevMonth();
console.log(`[CRON] Sending manager monthly reports for ${month}...`);

try {
const { rows: companies } = await pool.query(`SELECT DISTINCT c.id AS company_id, c.name AS company_name, u.id AS manager_id, u.email AS manager_email, u.name AS manager_name, s.status FROM companies c JOIN users u ON u.company_id = c.id AND u.role = 'manager' JOIN subscriptions s ON s.company_id = c.id WHERE s.status IN ('trialing', 'active') ORDER BY s.created_at DESC`);

```
for (const company of companies) {
  try {
    const { rows: totals } = await pool.query(`
      SELECT
        COUNT(*)                               AS total_detections,
        COUNT(*) FILTER (WHERE was_blocked)    AS total_blocked,
        COUNT(DISTINCT user_id)                AS active_employees
      FROM detections
      WHERE company_id = $1 AND month_year = $2
    `, [company.company_id, month]);

    const { rows: topTypes } = await pool.query(`
      SELECT data_type, COUNT(*) AS count
      FROM detections
      WHERE company_id = $1 AND month_year = $2
      GROUP BY data_type ORDER BY count DESC LIMIT 5
    `, [company.company_id, month]);

    const { rows: byEmployee } = await pool.query(`
      SELECT u.name AS employee_name, u.email AS employee_email, COUNT(*) AS count
      FROM detections d
      JOIN users u ON u.id = d.user_id
      WHERE d.company_id = $1 AND d.month_year = $2
      GROUP BY u.name, u.email
      ORDER BY count DESC
    `, [company.company_id, month]);

    const { rows: topPlatforms } = await pool.query(`
      SELECT platform, COUNT(*) AS count
      FROM detections
      WHERE company_id = $1 AND month_year = $2
      GROUP BY platform ORDER BY count DESC LIMIT 3
    `, [company.company_id, month]);

    const stats = {
      totalDetections: parseInt(totals[0]?.total_detections) || 0,
      totalBlocked:    parseInt(totals[0]?.total_blocked)    || 0,
      activeEmployees: parseInt(totals[0]?.active_employees) || 0,
      topDataTypes:    topTypes,
      byEmployee:      byEmployee,
      topPlatforms:    topPlatforms,
    };

    const html = managerMonthlyReport(
      company.manager_name || company.manager_email,
      company.company_name,
      month,
      stats
    );

    await send(
      company.manager_email,
      `AI Shield — ${company.company_name} Monthly Report (${formatMonthShort(month)})`,
      html
    );

    await pool.query(
      `INSERT INTO audit_logs (company_id, user_id, action, details)
       VALUES ($1, $2, 'monthly_report_sent', $3)`,
      [
        company.company_id,
        company.manager_id,
        JSON.stringify({ month, totalDetections: stats.totalDetections })
      ]
    ).catch(err => console.warn('audit_logs insert failed:', err.message));

  } catch (err) {
    console.error(`[CRON] Manager report failed for ${company.company_name}:`, err.message);
  }
}

console.log(`[CRON] Manager reports sent: ${companies.length}`);
```

} catch (err) {
console.error(’[CRON] manager_monthly_report error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// JOB 6 — Employee monthly summary (1st of month at 09:00 UTC)
// Personal summary for each employee
// ════════════════════════════════════════════════════════════
cron.schedule(‘0 9 1 * *’, async () => {
const month = prevMonth();
console.log(`[CRON] Sending employee monthly summaries for ${month}...`);

try {
const { rows: employees } = await pool.query(`SELECT DISTINCT u.id, u.email, u.name, u.company_id, c.name AS company_name, s.status FROM users u JOIN companies c ON c.id = u.company_id JOIN subscriptions s ON s.company_id = c.id WHERE u.role = 'employee' AND u.is_active = true AND s.status IN ('trialing', 'active')`);

```
for (const emp of employees) {
  try {
    const { rows: totals } = await pool.query(`
      SELECT
        COUNT(*)                              AS total_detections,
        COUNT(*) FILTER (WHERE was_blocked)   AS total_blocked
      FROM detections
      WHERE user_id = $1 AND month_year = $2
    `, [emp.id, month]);

    const { rows: topType } = await pool.query(`
      SELECT data_type, COUNT(*) AS count
      FROM detections
      WHERE user_id = $1 AND month_year = $2
      GROUP BY data_type ORDER BY count DESC LIMIT 1
    `, [emp.id, month]);

    const { rows: topPlatform } = await pool.query(`
      SELECT platform, COUNT(*) AS count
      FROM detections
      WHERE user_id = $1 AND month_year = $2
      GROUP BY platform ORDER BY count DESC LIMIT 1
    `, [emp.id, month]);

    const stats = {
      totalDetections: parseInt(totals[0]?.total_detections) || 0,
      totalBlocked:    parseInt(totals[0]?.total_blocked)    || 0,
      topDataType:     topType[0]    || null,
      topPlatform:     topPlatform[0] || null,
    };

    const html = employeeMonthlySummary(
      emp.name || emp.email,
      emp.company_name,
      month,
      stats
    );

    await send(
      emp.email,
      `Your AI Shield summary for ${formatMonthShort(month)}`,
      html
    );

  } catch (err) {
    console.error(`[CRON] Employee summary failed for ${emp.email}:`, err.message);
  }
}

console.log(`[CRON] Employee summaries sent: ${employees.length}`);
```

} catch (err) {
console.error(’[CRON] employee_monthly_summary error:’, err);
}
});

// ════════════════════════════════════════════════════════════
// STARTUP
// ════════════════════════════════════════════════════════════
console.log(’[CRON] Jobs active:’);
console.log(’       • trial_day7        — daily 09:00 UTC’);
console.log(’       • trial_day11       — daily 09:00 UTC’);
console.log(’       • trial_day13       — daily 09:00 UTC’);
console.log(’       • trial_expiry      — every hour’);
console.log(’       • manager_report    — 1st of month 08:00 UTC’);
console.log(’       • employee_summary  — 1st of month 09:00 UTC’);