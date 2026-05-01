const express = require(‘express’);
const router = express.Router();
const auth = require(’../middleware/auth’);
const { Pool } = require(‘pg’);

const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: process.env.NODE_ENV === ‘production’ ? { rejectUnauthorized: false } : false
});

router.get(’/summary’, auth, async (req, res) => {
try {
const company_id = req.user.company_id;

```
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
```

} catch (err) {
console.error(‘GET /detections/summary error:’, err);
res.status(500).json({ error: ‘Failed to load summary’ });
}
});

router.get(’/my’, auth, async (req, res) => {
try {
const user_id = req.user.id;

```
const result = await pool.query(
  'SELECT COUNT(*) as count FROM detections WHERE user_id = $1 AND detected_at::date = CURRENT_DATE',
  [user_id]
);
const countToday = parseInt(result.rows[0]?.count || 0);

res.json({ countToday });
```

} catch (err) {
console.error(‘GET /detections/my error:’, err);
res.status(500).json({ error: ‘Failed to load detections’ });
}
});

router.get(’/all’, auth, async (req, res) => {
try {
const company_id = req.user.company_id;
const limit = parseInt(req.query.limit) || 100;
const offset = parseInt(req.query.offset) || 0;

```
const result = await pool.query(
  'SELECT d.*, u.name as user_name, u.email as user_email FROM detections d LEFT JOIN users u ON d.user_id = u.id WHERE d.company_id = $1 ORDER BY d.detected_at DESC LIMIT $2 OFFSET $3',
  [company_id, limit, offset]
);

res.json({ detections: result.rows });
```

} catch (err) {
console.error(‘GET /detections/all error:’, err);
res.status(500).json({ error: ‘Failed to load detections’ });
}
});

router.get(’/team-members’, auth, async (req, res) => {
try {
const company_id = req.user.company_id;

```
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
```

} catch (err) {
console.error(‘GET /detections/team-members error:’, err);
res.status(500).json({ error: ‘Failed to load team members’ });
}
});

router.post(’/’, auth, async (req, res) => {
try {
const user_id = req.user.id;
const company_id = req.user.company_id;
const { platform, dataType, action, urlHost } = req.body;

```
if (!platform || !dataType) {
  return res.status(400).json({ error: 'Missing required fields' });
}

const month_year = new Date().toISOString().slice(0, 7);

await pool.query(
  'INSERT INTO detections (user_id, company_id, platform, data_type, employee_action, url_host, month_year, detected_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())',
  [user_id, company_id, platform, dataType, action || 'detected', urlHost, month_year]
);

res.json({ success: true });
```

} catch (err) {
console.error(‘POST /detections error:’, err);
res.status(500).json({ error: ‘Failed to log detection’ });
}
});

module.exports = router;