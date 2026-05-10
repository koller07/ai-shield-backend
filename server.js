// ============================================
// AI-SHIELD BACKEND — server.js v3
// Scenario C audit trail integrated
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
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || 'ai-shield-secret-key-change-in-production';

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      id:         decoded.id || decoded.userId,
      company_id: decoded.company_id || decoded.companyId,
      role:       decoded.role || 'employee',
    };
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido ou expirado' });
  }
}

// ════════════════════════════════════════════════════════
// ROTAS v2
// ════════════════════════════════════════════════════════
const authRouter       = require('./routes/auth');
const billingRouter    = require('./routes/billing');

// Endpoints novos (signup.html e popup.js v2 usam estes)
app.use('/auth',       authRouter);
app.use('/billing',    billingRouter);

// Alias legado — o dashboard antigo ainda chama /api/auth/*
app.use('/api/auth',   authRouter);

// ════════════════════════════════════════════════════════
// DETECTIONS ENDPOINTS - DADOS REAIS
// ════════════════════════════════════════════════════════

// GET /detections/summary - dados reais agregados
app.get('/detections/summary', authMiddleware, async (req, res) => {
  try {
    const company_id = req.user.company_id;

    const totalResult = await pool.query(
      'SELECT COUNT(*) as count FROM detections WHERE company_id = $1',
      [company_id]
    );
    const total = parseInt(totalResult.rows[0]?.count || 0);

    const h24Result = await pool.query(
      'SELECT COUNT(*) as count FROM detections WHERE company_id = $1 AND detected_at > NOW() - INTERVAL \'24 hours\'',
      [company_id]
    );
    const total_24h = parseInt(h24Result.rows[0]?.count || 0);

    const d7Result = await pool.query(
      'SELECT COUNT(*) as count FROM detections WHERE company_id = $1 AND detected_at > NOW() - INTERVAL \'7 days\'',
      [company_id]
    );
    const total_7d = parseInt(d7Result.rows[0]?.count || 0);

    const d30Result = await pool.query(
      'SELECT COUNT(*) as count FROM detections WHERE company_id = $1 AND detected_at > NOW() - INTERVAL \'30 days\'',
      [company_id]
    );
    const total_30d = parseInt(d30Result.rows[0]?.count || 0);

    const platformResult = await pool.query(
      'SELECT platform, COUNT(*) as count FROM detections WHERE company_id = $1 GROUP BY platform ORDER BY count DESC',
      [company_id]
    );
    const byPlatform = {};
    platformResult.rows.forEach(row => {
      byPlatform[row.platform] = parseInt(row.count);
    });

    const typeResult = await pool.query(
      'SELECT data_type, COUNT(*) as count FROM detections WHERE company_id = $1 GROUP BY data_type ORDER BY count DESC LIMIT 6',
      [company_id]
    );
    const byDataType = {};
    typeResult.rows.forEach(row => {
      byDataType[row.data_type] = parseInt(row.count);
    });

    const empResult = await pool.query(
      'SELECT COUNT(*) as count FROM users WHERE company_id = $1 AND role = \'employee\' AND is_active = true',
      [company_id]
    );
    const employee_count = parseInt(empResult.rows[0]?.count || 0);

    res.json({
      total,
      total_24h,
      total_7d,
      total_30d,
      byPlatform,
      byDataType,
      employee_count
    });

  } catch (err) {
    console.error('GET /detections/summary error:', err);
    res.status(500).json({ error: 'Failed to load summary' });
  }
});

// GET /detections/my - contagem do funcionário
app.get('/detections/my', authMiddleware, async (req, res) => {
  try {
    const user_id = req.user.id;

    const result = await pool.query(
      'SELECT COUNT(*) as count FROM detections WHERE user_id = $1 AND detected_at::date = CURRENT_DATE',
      [user_id]
    );
    const countToday = parseInt(result.rows[0]?.count || 0);

    res.json({ countToday });

  } catch (err) {
    console.error('GET /detections/my error:', err);
    res.status(500).json({ error: 'Failed to load detections' });
  }
});

// GET /detections/team-members - lista de funcionários com contagens reais
app.get('/detections/team-members', authMiddleware, async (req, res) => {
  try {
    const company_id = req.user.company_id;

    const result = await pool.query(
      'SELECT u.id, u.name, u.email, u.created_at, u.last_login, COUNT(d.id) as detection_count FROM users u LEFT JOIN detections d ON u.id = d.user_id AND d.detected_at > NOW() - INTERVAL \'30 days\' WHERE u.company_id = $1 AND u.role = \'employee\' AND u.is_active = true GROUP BY u.id, u.name, u.email, u.created_at, u.last_login ORDER BY detection_count DESC, u.name',
      [company_id]
    );

    const members = result.rows.map(row => ({
      id: row.id,
      name: row.name || row.email.split('@')[0],
      email: row.email,
      joined: row.created_at,
      last_login: row.last_login,
      detections: parseInt(row.detection_count || 0)
    }));

    res.json({ members });

  } catch (err) {
    console.error('GET /detections/team-members error:', err);
    res.status(500).json({ error: 'Failed to load team members' });
  }
});

// GET /detections/all - todas as detecções para a tabela
app.get('/detections/all', authMiddleware, async (req, res) => {
  try {
    const company_id = req.user.company_id;
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;

    const result = await pool.query(
      'SELECT d.*, u.name as user_name, u.email as user_email FROM detections d LEFT JOIN users u ON d.user_id = u.id WHERE d.company_id = $1 ORDER BY d.detected_at DESC LIMIT $2 OFFSET $3',
      [company_id, limit, offset]
    );

    res.json({ detections: result.rows });

  } catch (err) {
    console.error('GET /detections/all error:', err);
    res.status(500).json({ error: 'Failed to load detections' });
  }
});

// ════════════════════════════════════════════════════════
// 🆕 SCENARIO C — Audit trail with status updates
// ════════════════════════════════════════════════════════

// POST /detections - log nova detecção da extensão (Cenário C)
// Returns the ID so the extension can update the status later
app.post('/detections', authMiddleware, async (req, res) => {
  try {
    const user_id = req.user.id;
    const company_id = req.user.company_id;
    const { platform, dataType, action, urlHost, wasBlocked } = req.body;

    if (!platform || !dataType) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const month_year = new Date().toISOString().slice(0, 7);
    const finalAction = action || 'detected';

    // was_blocked is NULL by default (decision pending)
    // Only set true when explicitly removed
    const finalWasBlocked = (finalAction === 'removed') ? true
                          : (wasBlocked === true) ? true
                          : null;

    const result = await pool.query(
      `INSERT INTO detections
       (user_id, company_id, platform, data_type, employee_action, was_blocked, url_host, month_year, detected_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       RETURNING id`,
      [user_id, company_id, platform, dataType, finalAction, finalWasBlocked, urlHost, month_year]
    );

    res.json({
      success: true,
      id: result.rows[0].id    // 👈 Returned for Scenario C status updates
    });

  } catch (err) {
    console.error('POST /detections error:', err);
    res.status(500).json({ error: 'Failed to log detection' });
  }
});

// PATCH /detections/:id - atualizar ação tomada pelo funcionário
// Used by Scenario C to update status: 'removed' | 'sent_anyway' | 'ignored' | 'abandoned'
app.patch('/detections/:id', authMiddleware, async (req, res) => {
  try {
    const user_id = req.user.id;
    const company_id = req.user.company_id;
    const detectionId = req.params.id;
    const { action } = req.body;

    // Valid actions for Scenario C audit trail
    const validActions = ['removed', 'sent_anyway', 'ignored', 'abandoned'];
    if (!action || !validActions.includes(action)) {
      return res.status(400).json({
        error: 'Invalid action',
        valid: validActions
      });
    }

    // was_blocked depends on action: only 'removed' counts as blocked
    const wasBlocked = (action === 'removed') ? true : false;

    // Security: only update if detection belongs to this user
    const result = await pool.query(
      `UPDATE detections
       SET employee_action = $1,
           was_blocked = $2
       WHERE id = $3
         AND user_id = $4
         AND company_id = $5
       RETURNING id`,
      [action, wasBlocked, detectionId, user_id, company_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Detection not found or access denied' });
    }

    res.json({ success: true, id: result.rows[0].id, action });

  } catch (err) {
    console.error('PATCH /detections/:id error:', err);
    res.status(500).json({ error: 'Failed to update detection' });
  }
});

// ════════════════════════════════════════════════════════
// LEGACY BRIDGE
// Mantém os endpoints /api/detection e /api/dashboard/stats
// para que a extensão v1 e dashboard antigo não quebrem
// ════════════════════════════════════════════════════════

function legacyAuth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      userId:    decoded.userId || decoded.id,
      companyId: decoded.companyId || decoded.company_id,
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
      'INSERT INTO detections (user_id, company_id, platform, data_type, was_blocked, url_host, month_year, detected_at) VALUES ($1,$2,$3,$4,true,$5,$6,$7)',
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
      'SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE detected_at > NOW() - INTERVAL \'30 days\') AS monthly, COUNT(DISTINCT user_id) AS users FROM detections WHERE company_id = $1',
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
app.get('/health',     (_, res) => res.json({ status: 'ok', version: '3.0' }));
app.get('/api/health', (_, res) => res.json({ status: 'ok', version: '3.0' }));

// ════════════════════════════════════════════════════════
// CRON + START
// ════════════════════════════════════════════════════════
require('./cron');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️  AI-Shield v3 on port ${PORT}`);
  console.log(`   /auth/*       → routes/auth.js`);
  console.log(`   /api/auth/*   → routes/auth.js  (legacy alias)`);
  console.log(`   /detections/* → inline endpoints (Scenario C audit trail)`);
  console.log(`   /billing/*    → routes/billing.js`);
});
