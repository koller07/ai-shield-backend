// ================================================================
// routes/admin.js — v1
// Admin dashboard + CRM básico
//
// SEGURANÇA (Opção A): header `admin-password` === process.env.ADMIN_PASSWORD
//   Define ADMIN_PASSWORD no Railway (Variables). Sem essa variável,
//   o acesso é recusado (fail-closed).
//
// ENDPOINTS:
//   GET   /api/admin/stats               → estatísticas globais (dashboard)
//   GET   /api/admin/companies           → lista de empresas + estado (CRM lista)
//   GET   /api/admin/companies/:id       → detalhe de uma empresa (CRM detalhe)
//   PATCH /api/admin/companies/:id/stage → marca fase no funil (CRM pipeline)
// ================================================================
const express  = require('express');
const { Pool } = require('pg');
const router   = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Fases válidas do funil de vendas
const VALID_STAGES = ['lead', 'pilot', 'paying', 'churned'];

// ── Middleware: proteger tudo com a admin-password ──────────────
// Fail-closed: se ADMIN_PASSWORD não estiver definida, recusa sempre.
function adminAuth(req, res, next) {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    console.error('[ADMIN] ADMIN_PASSWORD não está definida no ambiente.');
    return res.status(500).json({ error: 'Admin não configurado no servidor.' });
  }
  const provided = req.headers['admin-password'];
  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  next();
}

router.use(adminAuth);

// ── GET /api/admin/stats ────────────────────────────────────────
// Estatísticas globais para os cartões do topo do dashboard
router.get('/stats', async (req, res) => {
  try {
    const [companies, users, detections, month] = await Promise.all([
      pool.query('SELECT COUNT(*) AS c FROM companies'),
      pool.query("SELECT COUNT(*) AS c FROM users"),
      pool.query('SELECT COUNT(*) AS c FROM detections'),
      pool.query("SELECT COUNT(*) AS c FROM detections WHERE detected_at > NOW() - INTERVAL '30 days'"),
    ]);

    res.json({
      success: true,
      totalCompanies:  parseInt(companies.rows[0].c)  || 0,
      totalUsers:      parseInt(users.rows[0].c)      || 0,
      totalDetections: parseInt(detections.rows[0].c) || 0,
      monthDetections: parseInt(month.rows[0].c)      || 0,
    });
  } catch (err) {
    console.error('GET /api/admin/stats error:', err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ── GET /api/admin/companies ────────────────────────────────────
// Lista de todas as empresas com estado, plano, seats, deteções e fase de funil
router.get('/companies', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id,
        c.name,
        c.company_code,
        c.pipeline_stage,
        c.created_at,
        mgr.email                         AS admin_email,
        COALESCE(sub.plan, 'trial')       AS plan_type,
        sub.status,
        sub.trial_ends_at,
        COALESCE(uc.user_count, 0)        AS user_count,
        COALESCE(dc.detection_count, 0)   AS detection_count,
        CASE WHEN sub.status IN ('trialing','active') THEN true ELSE false END AS is_active
      FROM companies c
      -- manager (primeiro criado) como email de contacto
      LEFT JOIN LATERAL (
        SELECT email FROM users
        WHERE company_id = c.id AND role = 'manager'
        ORDER BY created_at ASC LIMIT 1
      ) mgr ON true
      -- subscrição mais recente
      LEFT JOIN LATERAL (
        SELECT plan, status, trial_ends_at
        FROM subscriptions
        WHERE company_id = c.id
        ORDER BY created_at DESC LIMIT 1
      ) sub ON true
      -- contagem de utilizadores
      LEFT JOIN (
        SELECT company_id, COUNT(*) AS user_count
        FROM users GROUP BY company_id
      ) uc ON uc.company_id = c.id
      -- contagem de deteções
      LEFT JOIN (
        SELECT company_id, COUNT(*) AS detection_count
        FROM detections GROUP BY company_id
      ) dc ON dc.company_id = c.id
      ORDER BY c.created_at DESC
    `);

    // max_users por plano (mantém compatível com o dashboard, que mostra user_count / max_users)
    const MAX_BY_PLAN = { essentials: 10, compliance: 30, business: 75, trial: 30, enterprise: 999 };
    const companies = rows.map(r => ({
      id:              r.id,
      name:            r.name,
      company_code:    r.company_code,
      admin_email:     r.admin_email || '—',
      plan_type:       r.plan_type,
      status:          r.status || 'none',
      pipeline_stage:  r.pipeline_stage || 'lead',
      user_count:      parseInt(r.user_count)      || 0,
      max_users:       MAX_BY_PLAN[r.plan_type] || 30,
      detection_count: parseInt(r.detection_count) || 0,
      is_active:       r.is_active,
      trial_ends_at:   r.trial_ends_at,
      created_at:      r.created_at,
    }));

    res.json({ success: true, companies });
  } catch (err) {
    console.error('GET /api/admin/companies error:', err);
    res.status(500).json({ error: 'Failed to load companies' });
  }
});

// ── GET /api/admin/companies/:id ────────────────────────────────
// Detalhe de uma empresa: dados, subscrição, seats, deteções, membros
router.get('/companies/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const companyRes = await pool.query(
      `SELECT id, name, domain, company_code, pipeline_stage, created_at
       FROM companies WHERE id = $1`, [id]
    );
    if (!companyRes.rows.length) {
      return res.status(404).json({ error: 'Company not found' });
    }
    const company = companyRes.rows[0];

    const [sub, members, detStats, topTypes] = await Promise.all([
      pool.query(
        `SELECT plan, status, billing_cycle, trial_ends_at, current_period_end, created_at
         FROM subscriptions WHERE company_id = $1
         ORDER BY created_at DESC LIMIT 1`, [id]
      ),
      pool.query(
        `SELECT id, name, email, role, is_active, created_at, last_login
         FROM users WHERE company_id = $1 ORDER BY role, created_at`, [id]
      ),
      pool.query(
        `SELECT
           COUNT(*)                                                     AS total,
           COUNT(*) FILTER (WHERE detected_at > NOW() - INTERVAL '30 days') AS last_30d,
           COUNT(*) FILTER (WHERE employee_action = 'removed')         AS removed,
           COUNT(*) FILTER (WHERE employee_action IN ('ignored','sent_anyway')) AS sent_anyway
         FROM detections WHERE company_id = $1`, [id]
      ),
      pool.query(
        `SELECT data_type, COUNT(*) AS count
         FROM detections WHERE company_id = $1
         GROUP BY data_type ORDER BY count DESC LIMIT 5`, [id]
      ),
    ]);

    res.json({
      success: true,
      company: {
        ...company,
        pipeline_stage: company.pipeline_stage || 'lead',
      },
      subscription: sub.rows[0] || null,
      members: members.rows,
      detections: {
        total:       parseInt(detStats.rows[0]?.total)       || 0,
        last_30d:    parseInt(detStats.rows[0]?.last_30d)    || 0,
        removed:     parseInt(detStats.rows[0]?.removed)     || 0,
        sent_anyway: parseInt(detStats.rows[0]?.sent_anyway) || 0,
        top_types:   topTypes.rows,
      },
    });
  } catch (err) {
    console.error('GET /api/admin/companies/:id error:', err);
    res.status(500).json({ error: 'Failed to load company detail' });
  }
});

// ── PATCH /api/admin/companies/:id/stage ────────────────────────
// Marca a fase no funil: lead | pilot | paying | churned
router.patch('/companies/:id/stage', async (req, res) => {
  const { id } = req.params;
  const { stage } = req.body;
  if (!stage || !VALID_STAGES.includes(stage)) {
    return res.status(400).json({ error: 'Invalid stage', valid: VALID_STAGES });
  }
  try {
    const { rows } = await pool.query(
      `UPDATE companies SET pipeline_stage = $1 WHERE id = $2 RETURNING id, name, pipeline_stage`,
      [stage, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Company not found' });
    res.json({ success: true, company: rows[0] });
  } catch (err) {
    console.error('PATCH /api/admin/companies/:id/stage error:', err);
    res.status(500).json({ error: 'Failed to update stage' });
  }
});

module.exports = router;
