// ================================================================
// routes/auth.js — v4
// Separação Manager vs Funcionário
//
// CHANGES v4:
//   - welcome email now uses emails.welcome() (branded design)
//   - employee/join now sends emails.employeeWelcome() (new branded email)
//   - removed inline welcomeEmail() function
//
// CHANGES v3:
//   - signup now accepts and stores `plan` and `cycle` from signup.html
//   - subscriptions are created with the actual chosen plan (not hardcoded 'trial')
//
// ENDPOINTS:
//   POST /auth/signup          → cria manager + empresa (com plano escolhido)
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
const emails   = require('../emails');
const router   = express.Router();

const pool   = new Pool({ connectionString: process.env.DATABASE_URL });
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = `AI Shield <hello@getaishield.co>`;

// Valid plan keys accepted from signup form
const VALID_PLANS  = ['essentials', 'compliance', 'business'];
const VALID_CYCLES = ['monthly', 'annual'];

// ── POST /auth/signup ────────────────────────────────────
// Cria um MANAGER + a sua empresa + subscription (trial com plano escolhido)
// Chamado pela página signup.html do site
router.post('/signup', async (req, res) => {
  const { email, password, name, companyName, plan, cycle } = req.body;

  if (!email || !password || !companyName) {
    return res.status(400).json({ error: 'email, password e companyName são obrigatórios' });
  }

  // Validate plan (default to compliance if missing/invalid — most popular)
  const chosenPlan  = VALID_PLANS.includes(plan)   ? plan   : 'compliance';
  const chosenCycle = VALID_CYCLES.includes(cycle) ? cycle  : 'monthly';

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
      `INSERT INTO users (company_id, email, password_hash, name, role, is_active)
       VALUES ($1, $2, $3, $4, 'manager', true) RETURNING id, email, name, role`,
      [company.id, email, hash, name || email.split('@')[0]]
    );
    const user = userRes.rows[0];

    // Criar trial de 14 dias para a empresa COM o plano escolhido
    await client.query(
      `INSERT INTO subscriptions (company_id, created_by_user_id, plan, status, billing_cycle, trial_ends_at)
       VALUES ($1, $2, $3, 'trialing', $4, NOW() + INTERVAL '14 days')`,
      [company.id, user.id, chosenPlan, chosenCycle]
    );

    // Log
    await client.query(
      `INSERT INTO audit_logs (company_id, user_id, action, details)
       VALUES ($1, $2, 'signup', $3)`,
      [company.id, user.id, JSON.stringify({ email, companyName, plan: chosenPlan, cycle: chosenCycle })]
    );

    await client.query('COMMIT');

    // Email de boas-vindas (branded, with company code)
    await sendEmail(email, 'Welcome to AI Shield — your 14-day trial has started',
      emails.welcome(user.name, company.company_code)
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
              s.plan, s.status, s.billing_cycle, s.trial_ends_at, s.current_period_end
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
        billingCycle: row.billing_cycle,
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
      `INSERT INTO users (company_id, email, password_hash, name, role, is_active)
       VALUES ($1, $2, $3, $4, 'employee', true) RETURNING id, email, name, role`,
      [company.id, email, hash, name || email.split('@')[0]]
    );
    const user = userRes.rows[0];

    await client.query(
      `INSERT INTO audit_logs (company_id, user_id, action)
       VALUES ($1, $2, 'employee_joined')`,
      [company.id, user.id]
    );

    await client.query('COMMIT');

    // Email de boas-vindas ao funcionário (branded)
    await sendEmail(email, `Welcome to AI Shield — you're protected at ${company.name}`,
      emails.employeeWelcome(user.name, company.name)
    );

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
              s.plan, s.status, s.billing_cycle, s.trial_ends_at, s.current_period_end
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
        plan:         row.plan,
        status:       row.status,
        billingCycle: row.billing_cycle,
        trialEndsAt:  row.trial_ends_at,
        periodEnd:    row.current_period_end,
        isActive:     ['trialing', 'active'].includes(row.status),
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

module.exports = router;
