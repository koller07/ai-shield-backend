// ================================================================
// routes/detections.js — v2
// Funcionário POST → envia detecção da sua extensão
// Manager GET → lê TODAS as detecções da empresa
// ================================================================

const express  = require('express');
const { Pool } = require('pg');
const auth     = require('../middleware/auth');
const { managerOnly } = require('../middleware/auth');
const router   = express.Router();
const pool     = new Pool({ connectionString: process.env.DATABASE_URL });

// ── POST /detections ─────────────────────────────────────
// Chamado pela extensão Chrome do funcionário
// Qualquer utilizador autenticado pode enviar (manager ou employee)
router.post('/', auth, async (req, res) => {
  const { platform, dataType, wasBlocked, employeeAction, urlHost } = req.body;

  if (!platform || !dataType) {
    return res.status(400).json({ error: 'platform e dataType são obrigatórios' });
  }

  const monthYear = new Date().toISOString().slice(0, 7);

  try {
    await pool.query(
      `INSERT INTO detections
         (user_id, company_id, platform, data_type, was_blocked, employee_action, url_host, month_year)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        req.user.userId,
        req.user.companyId,
        platform.toLowerCase(),
        dataType.toUpperCase(),
        wasBlocked !== false,
        employeeAction || null,
        urlHost || null,
        monthYear,
      ]
    );

    res.status(201).json({ ok: true });

  } catch (err) {
    console.error('POST /detections:', err);
    res.status(500).json({ error: 'Erro ao guardar detecção.' });
  }
});

// ── GET /detections ──────────────────────────────────────
// MANAGER ONLY — lista detecções de todos os funcionários da empresa
// Query params: ?month=2026-04&userId=xxx&platform=chatgpt
router.get('/', managerOnly, async (req, res) => {
  const {
    month    = new Date().toISOString().slice(0, 7),
    userId,
    platform,
    limit    = 500,
  } = req.query;

  try {
    let query = `
      SELECT
        d.id, d.platform, d.data_type, d.was_blocked,
        d.employee_action, d.url_host, d.detected_at,
        u.name AS employee_name, u.email AS employee_email
      FROM detections d
      JOIN users u ON u.id = d.user_id
      WHERE d.company_id = $1 AND d.month_year = $2
    `;
    const params = [req.user.companyId, month];

    if (userId) {
      params.push(userId);
      query += ` AND d.user_id = $${params.length}`;
    }
    if (platform) {
      params.push(platform.toLowerCase());
      query += ` AND d.platform = $${params.length}`;
    }

    query += ` ORDER BY d.detected_at DESC LIMIT $${params.length + 1}`;
    params.push(Math.min(parseInt(limit), 1000));

    const { rows } = await pool.query(query, params);

    // Summary by type
    const byType     = rows.reduce((a, r) => ({ ...a, [r.data_type]:  (a[r.data_type]  || 0) + 1 }), {});
    const byPlatform = rows.reduce((a, r) => ({ ...a, [r.platform]:   (a[r.platform]   || 0) + 1 }), {});
    const byEmployee = rows.reduce((a, r) => ({
      ...a,
      [r.employee_email]: {
        name:  r.employee_name,
        email: r.employee_email,
        count: ((a[r.employee_email]?.count) || 0) + 1,
      }
    }), {});

    res.json({
      month,
      total:      rows.length,
      blocked:    rows.filter(r => r.was_blocked).length,
      detections: rows,
      byType,
      byPlatform,
      byEmployee: Object.values(byEmployee),
    });

  } catch (err) {
    console.error('GET /detections:', err);
    res.status(500).json({ error: 'Erro ao buscar detecções.' });
  }
});

// ── GET /detections/summary ──────────────────────────────
// MANAGER ONLY — cards de resumo no topo do dashboard
router.get('/summary', managerOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '30 days') AS total_30d,
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '7 days')  AS total_7d,
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '24 hours') AS total_24h,
         COUNT(*) FILTER (WHERE was_blocked AND detected_at >= NOW() - INTERVAL '30 days') AS blocked_30d,
         COUNT(DISTINCT user_id) FILTER (WHERE detected_at >= NOW() - INTERVAL '30 days') AS active_employees
       FROM detections
       WHERE company_id = $1`,
      [req.user.companyId]
    );

    const { rows: topTypes } = await pool.query(
      `SELECT data_type, COUNT(*) AS count
       FROM detections
       WHERE company_id = $1 AND detected_at >= NOW() - INTERVAL '30 days'
       GROUP BY data_type ORDER BY count DESC LIMIT 5`,
      [req.user.companyId]
    );

    res.json({ ...rows[0], topDataTypes: topTypes });

  } catch (err) {
    console.error('GET /detections/summary:', err);
    res.status(500).json({ error: 'Erro ao buscar resumo.' });
  }
});

// ── GET /detections/my ───────────────────────────────────
// EMPLOYEE — só as suas próprias detecções (para o popup da extensão)
router.get('/my', auth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  try {
    const { rows } = await pool.query(
      `SELECT COUNT(*) AS count_today
       FROM detections
       WHERE user_id = $1
         AND detected_at::date = $2`,
      [req.user.userId, today]
    );

    res.json({
      countToday: parseInt(rows[0]?.count_today) || 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── GET /detections/report ───────────────────────────────
// MANAGER ONLY — relatório GDPR exportável
router.get('/report', managerOnly, async (req, res) => {
  const month = req.query.month || new Date().toISOString().slice(0, 7);

  try {
    const company = await pool.query(
      'SELECT name FROM companies WHERE id = $1', [req.user.companyId]
    );

    const { rows } = await pool.query(
      `SELECT d.platform, d.data_type, d.was_blocked, d.employee_action,
              d.url_host, d.detected_at,
              u.name AS employee_name, u.email AS employee_email
       FROM detections d
       JOIN users u ON u.id = d.user_id
       WHERE d.company_id = $1 AND d.month_year = $2
       ORDER BY d.detected_at ASC`,
      [req.user.companyId, month]
    );

    await pool.query(
      `INSERT INTO audit_logs (company_id, user_id, action, details)
       VALUES ($1,$2,'report_export',$3)`,
      [req.user.companyId, req.user.userId, JSON.stringify({ month, total: rows.length })]
    );

    res.json({
      reportMonth:   month,
      generatedAt:   new Date().toISOString(),
      organisation:  company.rows[0]?.name || 'N/A',
      reportedBy:    req.user.email,
      framework:     'GDPR Article 32 — Technical Measures Documentation',
      totalEvents:   rows.length,
      blocked:       rows.filter(r => r.was_blocked).length,
      detections:    rows,
    });

  } catch (err) {
    console.error('GET /detections/report:', err);
    res.status(500).json({ error: 'Erro ao gerar relatório.' });
  }
});

module.exports = router;
