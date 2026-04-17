// ============================================================
// routes/detections.js
// Chrome extension sends detections here.
// Dashboard reads them back.
// ============================================================

const express  = require('express');
const { Pool } = require('pg');
const auth     = require('../middleware/auth');
const router   = express.Router();
const pool     = new Pool({ connectionString: process.env.DATABASE_URL });

// ─── POST /detections ──────────────────────────────────────
// Called by Chrome extension when sensitive data is detected
// Body: { platform, dataType, wasBlocked, employeeAction, urlHost }
router.post('/', auth, async (req, res) => {
  const { platform, dataType, wasBlocked, employeeAction, urlHost } = req.body;

  if (!platform || !dataType) {
    return res.status(400).json({ error: 'platform and dataType are required' });
  }

  const monthYear = new Date().toISOString().slice(0, 7); // '2026-04'

  try {
    await pool.query(
      `INSERT INTO detections
         (user_id, platform, data_type, was_blocked, employee_action, url_host, month_year)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        req.user.userId,
        platform.toLowerCase(),
        dataType.toUpperCase(),
        wasBlocked !== false,
        employeeAction || null,
        urlHost || null,
        monthYear
      ]
    );

    res.status(201).json({ ok: true });

  } catch (err) {
    console.error('POST /detections error:', err);
    res.status(500).json({ error: 'Failed to save detection' });
  }
});

// ─── GET /detections ───────────────────────────────────────
// Dashboard: list detections with optional month filter
// Query: ?month=2026-04&limit=100
router.get('/', auth, async (req, res) => {
  const month  = req.query.month || new Date().toISOString().slice(0, 7);
  const limit  = Math.min(parseInt(req.query.limit) || 200, 500);

  try {
    const { rows } = await pool.query(
      `SELECT id, platform, data_type, was_blocked,
              employee_action, url_host, detected_at
       FROM detections
       WHERE user_id = $1 AND month_year = $2
       ORDER BY detected_at DESC
       LIMIT $3`,
      [req.user.userId, month, limit]
    );

    // Summary by data type
    const byType = rows.reduce((acc, r) => {
      acc[r.data_type] = (acc[r.data_type] || 0) + 1;
      return acc;
    }, {});

    // Summary by platform
    const byPlatform = rows.reduce((acc, r) => {
      acc[r.platform] = (acc[r.platform] || 0) + 1;
      return acc;
    }, {});

    res.json({
      month,
      total:      rows.length,
      blocked:    rows.filter(r => r.was_blocked).length,
      detections: rows,
      byType,
      byPlatform,
    });

  } catch (err) {
    console.error('GET /detections error:', err);
    res.status(500).json({ error: 'Failed to fetch detections' });
  }
});

// ─── GET /detections/summary ───────────────────────────────
// Lightweight summary for dashboard header cards
// Last 30 days
router.get('/summary', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '30 days') AS total_30d,
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '7 days')  AS total_7d,
         COUNT(*) FILTER (WHERE detected_at >= NOW() - INTERVAL '24 hours') AS total_24h,
         COUNT(*) FILTER (WHERE was_blocked = true
                            AND detected_at >= NOW() - INTERVAL '30 days') AS blocked_30d
       FROM detections
       WHERE user_id = $1`,
      [req.user.userId]
    );

    // Top data types last 30 days
    const { rows: topTypes } = await pool.query(
      `SELECT data_type, COUNT(*) as count
       FROM detections
       WHERE user_id = $1
         AND detected_at >= NOW() - INTERVAL '30 days'
       GROUP BY data_type
       ORDER BY count DESC
       LIMIT 5`,
      [req.user.userId]
    );

    res.json({
      ...rows[0],
      topDataTypes: topTypes,
    });

  } catch (err) {
    console.error('GET /detections/summary error:', err);
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// ─── GET /detections/report ────────────────────────────────
// GDPR-ready audit report for a given month
// Returns structured JSON — frontend renders as PDF or table
router.get('/report', auth, async (req, res) => {
  const month = req.query.month || new Date().toISOString().slice(0, 7);

  try {
    const user = await pool.query(
      'SELECT email, name, company FROM users WHERE id = $1',
      [req.user.userId]
    );

    const { rows } = await pool.query(
      `SELECT platform, data_type, was_blocked,
              employee_action, url_host, detected_at
       FROM detections
       WHERE user_id = $1 AND month_year = $2
       ORDER BY detected_at ASC`,
      [req.user.userId, month]
    );

    // Log report export as audit event
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, details)
       VALUES ($1, 'report_export', $2)`,
      [req.user.userId, JSON.stringify({ month, totalDetections: rows.length })]
    );

    res.json({
      reportMonth:   month,
      generatedAt:   new Date().toISOString(),
      organisation:  user.rows[0]?.company || 'N/A',
      reportedBy:    user.rows[0]?.email,
      framework:     'GDPR Article 32 — Technical Measures Documentation',
      totalEvents:   rows.length,
      blockedEvents: rows.filter(r => r.was_blocked).length,
      detections:    rows,
    });

  } catch (err) {
    console.error('GET /detections/report error:', err);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

module.exports = router;
