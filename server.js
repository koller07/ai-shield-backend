// ============================================
// AI-SHIELD BACKEND — app.js v2
// SUBSTITUI o ficheiro anterior por completo
// ============================================

const express  = require('express');
const { Pool } = require('pg');
const cors     = require('cors');
const dotenv   = require('dotenv');
const jwt      = require('jsonwebtoken');

dotenv.config();

const app = express();

// ── Stripe webhook ANTES do express.json() ───────────────
app.use('/billing/webhook', express.raw({ type: 'application/json' }));

app.use(express.json());
app.use(cors());

// ════════════════════════════════════════════════════════
// ROTAS v2
// ════════════════════════════════════════════════════════
const authRouter       = require('./routes/auth');
const detectionsRouter = require('./routes/detections');
const billingRouter    = require('./routes/billing');

// Endpoints novos (signup.html e popup.js v2 usam estes)
app.use('/auth',       authRouter);
app.use('/detections', detectionsRouter);
app.use('/billing',    billingRouter);

// Alias legado — o dashboard antigo ainda chama /api/auth/*
app.use('/api/auth',   authRouter);

// ════════════════════════════════════════════════════════
// BASE DE DADOS
// ════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query('SELECT NOW()', (err, result) => {
  if (err) console.error('❌ DB error:', err.message);
  else     console.log('✅ DB connected:', result.rows[0].now);
});

// ════════════════════════════════════════════════════════
// LEGACY BRIDGE
// Mantém os endpoints /api/detection e /api/dashboard/stats
// para que a extensão v1 e dashboard antigo não quebrem
// ════════════════════════════════════════════════════════

const JWT_SECRET = process.env.JWT_SECRET || 'ai-shield-secret-key-change-in-production';

function legacyAuth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      userId:    decoded.userId || decoded.id,
      companyId: decoded.companyId,
      role:      decoded.role || 'employee',
    };
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido ou expirado' });
  }
}

// Extensão antiga enviava para /api/detection (singular)
app.post('/api/detection', legacyAuth, async (req, res) => {
  const { detectionType, aiPlatform, url, timestamp } = req.body;
  try {
    let urlHost = null;
    try { urlHost = url ? new URL(url).hostname : null; } catch (_) {}
    await pool.query(
      `INSERT INTO detections
         (user_id, company_id, platform, data_type, was_blocked, url_host, month_year, detected_at)
       VALUES ($1,$2,$3,$4,true,$5,$6,$7)`,
      [
        req.user.userId,
        req.user.companyId,
        (aiPlatform   || 'unknown').toLowerCase(),
        (detectionType || 'UNKNOWN').toUpperCase(),
        urlHost,
        new Date().toISOString().slice(0, 7),
        timestamp ? new Date(timestamp) : new Date(),
      ]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('/api/detection error:', err.message);
    res.status(500).json({ error: 'Failed to save detection' });
  }
});

// Dashboard stats legado
app.get('/api/dashboard/stats', legacyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         COUNT(*)                                                          AS total,
         COUNT(*) FILTER (WHERE detected_at > NOW() - INTERVAL '30 days') AS monthly,
         COUNT(DISTINCT user_id)                                           AS users
       FROM detections WHERE company_id = $1`,
      [req.user.companyId]
    );
    res.json({
      totalDetections: parseInt(rows[0].total)   || 0,
      monthDetections: parseInt(rows[0].monthly) || 0,
      activeUsers:     parseInt(rows[0].users)   || 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Health checks
app.get('/health',     (_, res) => res.json({ status: 'ok', version: '2.0' }));
app.get('/api/health', (_, res) => res.json({ status: 'ok', version: '2.0' }));

// ════════════════════════════════════════════════════════
// CRON + START
// ════════════════════════════════════════════════════════
require('./cron');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️  AI-Shield v2 on port ${PORT}`);
  console.log(`   /auth/*       → routes/auth.js`);
  console.log(`   /api/auth/*   → routes/auth.js  (legacy alias)`);
  console.log(`   /detections/* → routes/detections.js`);
  console.log(`   /billing/*    → routes/billing.js`);
});
