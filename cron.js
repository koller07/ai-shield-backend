// ================================================================
// cron.js — v2
// Tarefas automáticas agendadas
//
// JOBS:
// 1. Trial ending in 3 days    → 09:00 UTC diário
// 2. Trial expiry check        → a cada hora
// 3. Manager monthly report    → dia 1 do mês, 08:00 UTC
// 4. Employee monthly summary  → dia 1 do mês, 09:00 UTC
// ================================================================

const cron   = require('node-cron');
const { Pool } = require('pg');
const { Resend } = require('resend');
const emails = require('./emails');
const { managerMonthlyReport, employeeMonthlySummary } = require('./emails/monthly-reports');

const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = `AI Shield <hello@getaishield.co>`;

// ─── Helper: send email ───────────────────────────────────
async function send(to, subject, html) {
  try {
    await resend.emails.send({ from: FROM, to, subject, html });
    console.log(`[CRON] Email sent: ${subject} → ${to}`);
  } catch (err) {
    console.error(`[CRON] Email failed to ${to}:`, err.message);
  }
}

// ─── Helper: send once per type ──────────────────────────
async function sendOnce(userId, type, to, subject, html) {
  const { rows } = await pool.query(
    `SELECT id FROM email_log
     WHERE user_id = $1 AND email_type = $2
       AND sent_at > NOW() - INTERVAL '20 hours'`,
    [userId, type]
  );
  if (rows.length) return;
  await send(to, subject, html);
  await pool.query(
    'INSERT INTO email_log (user_id, email_type) VALUES ($1,$2)',
    [userId, type]
  );
}

// ─── Get previous month string ────────────────────────────
function prevMonth() {
  const d = new Date();
  d.setDate(1);
  d.setMonth(d.getMonth() - 1);
  return d.toISOString().slice(0, 7); // 'YYYY-MM'
}

// ════════════════════════════════════════════════════════════
// JOB 1 — Trial ending in 3 days (daily at 09:00 UTC)
// ════════════════════════════════════════════════════════════
cron.schedule('0 9 * * *', async () => {
  console.log('[CRON] Checking trials ending in 3 days...');
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.email, u.name, s.trial_ends_at
      FROM subscriptions s
      JOIN users u ON u.id = s.created_by_user_id
      WHERE s.status = 'trialing'
        AND s.trial_ends_at BETWEEN NOW() + INTERVAL '2 days'
                                AND NOW() + INTERVAL '4 days'
    `);

    for (const row of rows) {
      const days = Math.ceil((new Date(row.trial_ends_at) - Date.now()) / 86400000);
      await sendOnce(
        row.id, 'trial_ending_3d', row.email,
        `Your AI Shield trial ends in ${days} day${days !== 1 ? 's' : ''}`,
        emails.trialATerminar(row.name || row.email, days)
      );
    }
  } catch (err) {
    console.error('[CRON] trial_ending_3d error:', err);
  }
});

// ════════════════════════════════════════════════════════════
// JOB 2 — Expire overdue trials (every hour)
// ════════════════════════════════════════════════════════════
cron.schedule('0 * * * *', async () => {
  try {
    const { rows } = await pool.query(`
      UPDATE subscriptions SET status = 'expired', updated_at = NOW()
      WHERE status = 'trialing' AND trial_ends_at < NOW()
      RETURNING company_id, created_by_user_id AS user_id
    `);

    for (const row of rows) {
      const user = await pool.query(
        'SELECT email, name FROM users WHERE id = $1', [row.user_id]
      );
      if (user.rows[0]) {
        await sendOnce(
          row.user_id, 'trial_expired', user.rows[0].email,
          'Your AI Shield trial has ended',
          emails.trialExpirado(user.rows[0].name || user.rows[0].email)
        );
      }
    }

    if (rows.length > 0) console.log(`[CRON] Expired ${rows.length} trial(s)`);
  } catch (err) {
    console.error('[CRON] expire_trials error:', err);
  }
});

// ════════════════════════════════════════════════════════════
// JOB 3 — Manager monthly report (1st of month at 08:00 UTC)
// ════════════════════════════════════════════════════════════
cron.schedule('0 8 1 * *', async () => {
  const month = prevMonth();
  console.log(`[CRON] Sending manager monthly reports for ${month}...`);

  try {
    // Get all active companies with their manager
    const { rows: companies } = await pool.query(`
      SELECT DISTINCT
        c.id AS company_id, c.name AS company_name,
        u.id AS manager_id, u.email AS manager_email, u.name AS manager_name,
        s.status
      FROM companies c
      JOIN users u ON u.company_id = c.id AND u.role = 'manager'
      JOIN subscriptions s ON s.company_id = c.id
      WHERE s.status IN ('trialing', 'active')
      ORDER BY s.created_at DESC
    `);

    for (const company of companies) {
      try {
        // Aggregate stats for this company for prev month
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
          totalDetections:  parseInt(totals[0]?.total_detections)  || 0,
          totalBlocked:     parseInt(totals[0]?.total_blocked)     || 0,
          activeEmployees:  parseInt(totals[0]?.active_employees)  || 0,
          topDataTypes:     topTypes,
          byEmployee:       byEmployee,
          topPlatforms:     topPlatforms,
        };

        const html = managerMonthlyReport(
          company.manager_name || company.manager_email,
          company.company_name,
          month,
          stats
        );

        await send(
          company.manager_email,
          `AI Shield — ${company.company_name} Monthly Report`,
          html
        );

        // Log in audit
        await pool.query(
          `INSERT INTO audit_logs (company_id, user_id, action, details)
           VALUES ($1,$2,'monthly_report_sent',$3)`,
          [company.company_id, company.manager_id,
           JSON.stringify({ month, totalDetections: stats.totalDetections })]
        );

      } catch (err) {
        console.error(`[CRON] Manager report failed for ${company.company_name}:`, err.message);
      }
    }

    console.log(`[CRON] Manager reports sent: ${companies.length}`);

  } catch (err) {
    console.error('[CRON] manager_monthly_report error:', err);
  }
});

// ════════════════════════════════════════════════════════════
// JOB 4 — Employee monthly summary (1st of month at 09:00 UTC)
// ════════════════════════════════════════════════════════════
cron.schedule('0 9 1 * *', async () => {
  const month = prevMonth();
  console.log(`[CRON] Sending employee monthly summaries for ${month}...`);

  try {
    // Get all active employees whose company has an active subscription
    const { rows: employees } = await pool.query(`
      SELECT DISTINCT
        u.id, u.email, u.name, u.company_id,
        c.name AS company_name, s.status
      FROM users u
      JOIN companies c ON c.id = u.company_id
      JOIN subscriptions s ON s.company_id = c.id
      WHERE u.role = 'employee'
        AND s.status IN ('trialing', 'active')
    `);

    for (const emp of employees) {
      try {
        // Their personal stats for prev month
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

  } catch (err) {
    console.error('[CRON] employee_monthly_summary error:', err);
  }
});

// ─── Helper ──────────────────────────────────────────────
function formatMonthShort(monthStr) {
  const [year, month] = monthStr.split('-');
  const names = ['Jan','Feb','Mar','Apr','May','Jun',
                 'Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${names[parseInt(month, 10) - 1]} ${year}`;
}

console.log('[CRON] Jobs active: trial_ending, trial_expiry, manager_report (1st/month), employee_summary (1st/month)');
