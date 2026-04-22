// ================================================================
// middleware/auth.js — v2
// JWT verification + role helpers
// ================================================================

const jwt = require('jsonwebtoken');

// ── Base middleware — verify JWT ─────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token em falta ou inválido.' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    req.user = {
      userId:    decoded.userId || decoded.id,
      email:     decoded.email,
      role:      decoded.role,
      companyId: decoded.companyId,
    };
    next();
  } catch (err) {
    res.status(401).json({
      error: err.name === 'TokenExpiredError' ? 'Token expirado.' : 'Token inválido.'
    });
  }
}

// ── Manager-only middleware ──────────────────────────────
// Use on dashboard routes: only managers can access
function managerOnly(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'manager') {
      return res.status(403).json({
        error: 'Access denied. Dashboard is for account managers only.'
      });
    }
    next();
  });
}

// ── Active subscription middleware ───────────────────────
// Blocks access if company subscription is not active/trialing
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT status FROM subscriptions
       WHERE company_id = $1
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.companyId]
    );

    const status = rows[0]?.status;
    if (!['trialing', 'active'].includes(status)) {
      return res.status(402).json({
        error: 'Subscription required.',
        status: status || 'none',
      });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar subscrição.' });
  }
}

module.exports = auth;
module.exports.managerOnly             = managerOnly;
module.exports.requireActiveSubscription = requireActiveSubscription;
