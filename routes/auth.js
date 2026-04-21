// ================================================================
// routes/auth.js — v2
// Separação Manager vs Funcionário
//
// ENDPOINTS:
//   POST /auth/signup          → cria manager + empresa
//   POST /auth/login           → login para managers (dashboard)
//   POST /auth/employee/join   → funcionário entra com company_code
//   POST /auth/employee/login  → login do funcionário (extensão)
//   GET  /auth/me              → dados do utilizador actual
// ================================================================

const express  = require('express');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');
const { Resend } = require('resend');
const auth     = require('../middleware/auth');
const router   = express.Router();

const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = `AI Shield <hello@getaishield.co>`;

// ── POST /auth/signup ────────────────────────────────────
// Cria um MANAGER + a sua empresa
// Chamado pela página signup.html do site
router.post('/signup', async (req, res) => {
  const { email, password, name, companyName } = req.body;

  if (!email || !password || !companyName) {
    return res.status(400).json({ error: 'email, password e companyName são obrigatórios' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar email duplicado
    const exists = await client.query(
      'SELECT id FROM users WHERE email = $1', [email]
    );
    if (exists.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Este email já está registado.' });
    }

    // Criar empresa
    const companyRes = await client.query(
      `INSERT INTO companies (name, domain)
       VALUES ($1, $2) RETURNING id, name, company_code`,
      [companyName, email.split('@')[1] || null]
    );
    const company = companyRes.rows[0];

    // Criar manager
    const hash    = await bcrypt.hash(password, 12);
    const userRes = await client.query(
      `INSERT INTO users (company_id, email, password_hash, name, role)
       VALUES ($1, $2, $3, $4, 'manager') RETURNING id, email, name, role`,
      [company.id, email, hash, name || email.split('@')[0]]
    );
    const user = userRes.rows[0];

    // Criar trial de 14 dias para a empresa
    await client.query(
      `INSERT INTO subscriptions (company_id, created_by_user_id, plan, status, trial_ends_at)
       VALUES ($1, $2, 'trial', 'trialing', NOW() + INTERVAL '14 days')`,
      [company.id, user.id]
    );

    // Log
    await client.query(
      `INSERT INTO audit_logs (company_id, user_id, action, details)
       VALUES ($1, $2, 'signup', $3)`,
      [company.id, user.id, JSON.stringify({ email, companyName })]
    );

    await client.query('COMMIT');

    // Email de boas-vindas
    await sendEmail(email, 'Welcome to AI Shield — your 14-day trial has started',
      welcomeEmail(user.name, company.company_code)
    );

    // JWT
    const token = signToken(user, company);

    res.status(201).json({
      token,
      user:    { id: user.id, email: user.email, name: user.name, role: user.role },
      company: { id: company.id, name: company.name, companyCode: company.company_code },
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /auth/signup:', err);
    res.status(500).json({ error: 'Erro interno. Tenta novamente.' });
  } finally {
    client.release();
  }
});

// ── POST /auth/login ─────────────────────────────────────
// Login para MANAGERS — acesso ao dashboard web
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email e password são obrigatórios' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.role, u.password_hash,
              c.id AS company_id, c.name AS company_name, c.company_code,
              s.plan, s.status, s.trial_ends_at, s.current_period_end
       FROM users u
       JOIN companies c ON c.id = u.company_id
       LEFT JOIN subscriptions s ON s.company_id = c.id
       WHERE u.email = $1 AND u.role = 'manager'
       ORDER BY s.created_at DESC LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Email ou password incorrectos.' });
    }

    const row   = rows[0];
    const valid = await bcrypt.compare(password, row.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Email ou password incorrectos.' });
    }

    const user    = { id: row.id,         email: row.email, name: row.name, role: row.role };
    const company = { id: row.company_id, name: row.company_name, companyCode: row.company_code };
    const token   = signToken(user, company);

    res.json({
      token,
      user,
      company,
      subscription: {
        plan:         row.plan,
        status:       row.status,
        trialEndsAt:  row.trial_ends_at,
        periodEnd:    row.current_period_end,
        isActive:     ['trialing', 'active'].includes(row.status),
      },
    });

  } catch (err) {
    console.error('POST /auth/login:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── POST /auth/employee/join ─────────────────────────────
// Funcionário usa o Company Code para se registar
// Chamado pela extensão Chrome (primeiro acesso)
router.post('/employee/join', async (req, res) => {
  const { email, password, name, companyCode } = req.body;

  if (!email || !password || !companyCode) {
    return res.status(400).json({
      error: 'email, password e companyCode são obrigatórios'
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar company code
    const companyRes = await client.query(
      `SELECT c.id, c.name, s.status, s.trial_ends_at
       FROM companies c
       LEFT JOIN subscriptions s ON s.company_id = c.id
       WHERE c.company_code = $1
       ORDER BY s.created_at DESC LIMIT 1`,
      [companyCode.toUpperCase()]
    );

    if (!companyRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        error: 'Company code inválido. Pede o código correcto ao teu gestor.'
      });
    }

    const company = companyRes.rows[0];

    // Verificar se a empresa tem plano activo
    const validStatuses = ['trialing', 'active'];
    if (!validStatuses.includes(company.status)) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'A subscrição da empresa está inactiva. Contacta o teu gestor.'
      });
    }

    // Verificar email duplicado
    const exists = await client.query(
      'SELECT id FROM users WHERE email = $1', [email]
    );
    if (exists.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este email já está registado. Usa o login normal.'
      });
    }

    // Criar funcionário
    const hash    = await bcrypt.hash(password, 12);
    const userRes = await client.query(
      `INSERT INTO users (company_id, email, password_hash, name, role)
       VALUES ($1, $2, $3, $4, 'employee') RETURNING id, email, name, role`,
      [company.id, email, hash, name || email.split('@')[0]]
    );
    const user = userRes.rows[0];

    await client.query(
      `INSERT INTO audit_logs (company_id, user_id, action)
       VALUES ($1, $2, 'employee_joined')`,
      [company.id, user.id]
    );

    await client.query('COMMIT');

    const token = signToken(user, company);

    res.status(201).json({
      token,
      user:    { id: user.id, email: user.email, name: user.name, role: user.role },
      company: { id: company.id, name: company.name },
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /auth/employee/join:', err);
    res.status(500).json({ error: 'Erro interno.' });
  } finally {
    client.release();
  }
});

// ── POST /auth/employee/login ────────────────────────────
// Login do funcionário — usado pela extensão Chrome
router.post('/employee/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email e password são obrigatórios' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.role, u.password_hash,
              c.id AS company_id, c.name AS company_name,
              s.status, s.trial_ends_at, s.plan
       FROM users u
       JOIN companies c ON c.id = u.company_id
       LEFT JOIN subscriptions s ON s.company_id = c.id
       WHERE u.email = $1 AND u.role = 'employee'
       ORDER BY s.created_at DESC LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Email ou password incorrectos.' });
    }

    const row   = rows[0];
    const valid = await bcrypt.compare(password, row.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Email ou password incorrectos.' });
    }

    // Verificar se a empresa ainda tem plano activo
    const active = ['trialing', 'active'].includes(row.status);

    const user    = { id: row.id, email: row.email, name: row.name, role: row.role };
    const company = { id: row.company_id, name: row.company_name };
    const token   = signToken(user, company);

    res.json({
      token,
      user,
      company,
      // Funcionário só precisa de saber se está activo, não detalhes do plano
      active,
      message: active
        ? 'Monitoring active'
        : 'Company subscription inactive — contact your manager',
    });

  } catch (err) {
    console.error('POST /auth/employee/login:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── GET /auth/me ─────────────────────────────────────────
// Valida token e devolve dados do utilizador actual
router.get('/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.role,
              c.id AS company_id, c.name AS company_name, c.company_code,
              s.plan, s.status, s.trial_ends_at, s.current_period_end
       FROM users u
       JOIN companies c ON c.id = u.company_id
       LEFT JOIN subscriptions s ON s.company_id = c.id
       WHERE u.id = $1
       ORDER BY s.created_at DESC LIMIT 1`,
      [req.user.userId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Utilizador não encontrado.' });
    }

    const row = rows[0];
    res.json({
      user: { id: row.id, email: row.email, name: row.name, role: row.role },
      company: {
        id:          row.company_id,
        name:        row.company_name,
        companyCode: row.company_code, // só visível para managers no frontend
      },
      subscription: {
        plan:        row.plan,
        status:      row.status,
        trialEndsAt: row.trial_ends_at,
        periodEnd:   row.current_period_end,
        isActive:    ['trialing', 'active'].includes(row.status),
      },
    });

  } catch (err) {
    console.error('GET /auth/me:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ─── Helpers ─────────────────────────────────────────────
function signToken(user, company) {
  return jwt.sign(
    {
      userId:    user.id,
      email:     user.email,
      role:      user.role,
      companyId: company.id,
    },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function sendEmail(to, subject, html) {
  try {
    await resend.emails.send({ from: FROM, to, subject, html });
  } catch (err) {
    console.error('Email send failed:', err.message);
  }
}

function welcomeEmail(name, companyCode) {
  return `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:40px 32px">
      <h1 style="font-size:22px;font-weight:800;color:#0D1117;margin:0 0 12px">
        🛡️ Your 14-day trial has started.
      </h1>
      <p style="color:#3A4250;font-size:15px;line-height:1.65;margin:0 0 16px">
        Hi ${name}, welcome to AI Shield.
      </p>
      <p style="color:#3A4250;font-size:15px;line-height:1.65;margin:0 0 24px">
        Share this code with your team so they can activate the Chrome extension:
      </p>
      <div style="background:#F7F8FA;border:2px dashed #E3E8EF;border-radius:12px;
                  padding:20px;text-align:center;margin-bottom:24px">
        <div style="font-size:11px;color:#9CA3AF;font-weight:600;letter-spacing:.1em;
                    text-transform:uppercase;margin-bottom:8px">Company Code</div>
        <div style="font-size:32px;font-weight:800;color:#0052CC;letter-spacing:.12em;
                    font-family:monospace">${companyCode}</div>
      </div>
      <a href="https://getaishield.co/dashboard.html"
         style="display:inline-block;background:#0052CC;color:white;font-weight:600;
                padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">
        Open Dashboard →
      </a>
    </div>
  `;
}

module.exports = router;
