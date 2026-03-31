// ============================================
// AI-SHIELD BACKEND SERVER
// Com autenticação JWT
// ============================================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// JWT Secret (adicionar no .env: JWT_SECRET=sua-chave-secreta-muito-longa)
const JWT_SECRET = process.env.JWT_SECRET || 'ai-shield-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d'; // Token expira em 7 dias

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected:', res.rows[0]);
  }
});

// Initialize database tables
//async function initializeDatabase() {
// try {
//  const sql = fs.readFileSync('./init.sql', 'utf8');
//await pool.query(sql);
//console.log('Database tables initialized');
//} catch (error) {
// console.error('Error initializing database:', error);
//}
//}
//
//initializeDatabase();

// ============================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado' });
    }
    req.user = user; // { userId, companyId, email }
    next();
  });
}

// ============================================
// ENDPOINTS DE AUTENTICAÇÃO
// ============================================

// 1. SIGNUP - Criar conta
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, fullName, companyName, plan = 'starter' } = req.body;

  try {
    // Validação básica
    if (!email || !password || !companyName) {
      return res.status(400).json({ 
        error: 'Email, senha e nome da empresa são obrigatórios' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Senha deve ter no mínimo 6 caracteres' 
      });
    }

    // Verificar se email já existe
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Email já cadastrado' 
      });
    }

    // Hash da senha
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Criar empresa
    const companyResult = await pool.query(
      `INSERT INTO companies (name, admin_email, plan, active, trial_ends_at) 
       VALUES ($1, $2, $3, true, NOW() + INTERVAL '14 days') 
       RETURNING id, name, plan`,
      [companyName, email.toLowerCase(), plan]
    );

    const company = companyResult.rows[0];

    // Criar usuário admin
    const userResult = await pool.query(
      `INSERT INTO users (company_id, email, password_hash, full_name, role, active) 
       VALUES ($1, $2, $3, $4, 'admin', true) 
       RETURNING id, email, full_name, role`,
      [company.id, email.toLowerCase(), passwordHash, fullName || companyName]
    );

    const user = userResult.rows[0];

    // Gerar JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        companyId: company.id, 
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Enviar email de boas-vindas (async, não bloquear resposta)
    sendWelcomeEmail(email, fullName || companyName, company.name).catch(err => {
      console.error('Erro ao enviar email de boas-vindas:', err);
    });

    // Retornar dados
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role
      },
      company: {
        id: company.id,
        name: company.name,
        plan: company.plan
      },
      message: 'Conta criada com sucesso! Trial de 14 dias ativado.'
    });

  } catch (error) {
    console.error('Erro no signup:', error);
    res.status(500).json({ 
      error: 'Erro ao criar conta. Tente novamente.' 
    });
  }
});

// 2. LOGIN - Fazer login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validação básica
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email e senha são obrigatórios' 
      });
    }

    // Buscar usuário
    const userResult = await pool.query(
      `SELECT u.id, u.email, u.password_hash, u.full_name, u.role, u.company_id, u.active,
              c.name as company_name, c.plan, c.active as company_active
       FROM users u
       JOIN companies c ON u.company_id = c.id
       WHERE u.email = $1`,
      [email.toLowerCase()]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Email ou senha incorretos' 
      });
    }

    const user = userResult.rows[0];

    // Verificar se usuário está ativo
    if (!user.active) {
      return res.status(403).json({ 
        error: 'Conta desativada. Entre em contato com o suporte.' 
      });
    }

    // Verificar se empresa está ativa
    if (!user.company_active) {
      return res.status(403).json({ 
        error: 'Empresa desativada. Verifique o pagamento.' 
      });
    }

    // Verificar senha
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({ 
        error: 'Email ou senha incorretos' 
      });
    }

    // Atualizar last_login
    await pool.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );

    // Gerar JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        companyId: user.company_id, 
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Retornar dados
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role
      },
      company: {
        id: user.company_id,
        name: user.company_name,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ 
      error: 'Erro ao fazer login. Tente novamente.' 
    });
  }
});

// 3. ME - Obter dados do usuário atual
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.company_id, u.last_login,
              c.name as company_name, c.plan, c.active as company_active
       FROM users u
       JOIN companies c ON u.company_id = c.id
       WHERE u.id = $1`,
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    res.json({
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        lastLogin: user.last_login
      },
      company: {
        id: user.company_id,
        name: user.company_name,
        plan: user.plan,
        active: user.company_active
      }
    });

  } catch (error) {
    console.error('Erro ao obter usuário:', error);
    res.status(500).json({ error: 'Erro ao obter dados do usuário' });
  }
});

// ============================================
// ENDPOINTS PROTEGIDOS (requerem autenticação)
// ============================================

// Health check (público)
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'AI-Shield Backend is running' });
});

// Receber detecção (protegido)
app.post('/api/detection', authenticateToken, async (req, res) => {
  const { detectionType, aiPlatform, timestamp, url } = req.body;
  
  try {
    await pool.query(
      `INSERT INTO detections (user_id, company_id, detection_type, ai_platform, url, timestamp) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.user.userId, req.user.companyId, detectionType, aiPlatform, url, timestamp || new Date()]
    );
    
    res.json({ success: true, message: 'Detection recorded' });
  } catch (error) {
    console.error('Error saving detection:', error);
    res.status(500).json({ error: 'Failed to save detection' });
  }
});

// Get report (protegido)
app.get('/api/report/:month/:year', authenticateToken, async (req, res) => {
  const { month, year } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT u.email, u.full_name, d.detection_type, COUNT(*) as count 
       FROM detections d
       JOIN users u ON d.user_id = u.id
       WHERE d.company_id = $1 
       AND EXTRACT(MONTH FROM d.timestamp) = $2 
       AND EXTRACT(YEAR FROM d.timestamp) = $3 
       GROUP BY u.email, u.full_name, d.detection_type
       ORDER BY count DESC`,
      [req.user.companyId, month, year]
    );
    
    const totalDetections = result.rows.reduce((sum, row) => sum + parseInt(row.count), 0);
    
    res.json({
      month,
      year,
      totalDetections,
      finePrevented: totalDetections * 50000,
      byUser: result.rows
    });
  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Get detections (protegido)
app.get('/api/detections', authenticateToken, async (req, res) => {
  const limit = req.query.limit || 100;
  
  try {
    const result = await pool.query(
      `SELECT d.*, u.email, u.full_name
       FROM detections d
       LEFT JOIN users u ON d.user_id = u.id
       WHERE d.company_id = $1 
       ORDER BY d.timestamp DESC 
       LIMIT $2`,
      [req.user.companyId, limit]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching detections:', error);
    res.status(500).json({ error: 'Failed to fetch detections' });
  }
});

// Get company users (protegido - só admin)
app.get('/api/company/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, full_name, role, active, last_login, created_at
       FROM users
       WHERE company_id = $1
       ORDER BY created_at DESC`,
      [req.user.companyId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get dashboard stats (protegido)
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    // Total detections
    const totalResult = await pool.query(
      'SELECT COUNT(*) as total FROM detections WHERE company_id = $1',
      [req.user.companyId]
    );

    // Detections this month
    const monthResult = await pool.query(
      `SELECT COUNT(*) as total FROM detections 
       WHERE company_id = $1 
       AND EXTRACT(MONTH FROM timestamp) = EXTRACT(MONTH FROM NOW())
       AND EXTRACT(YEAR FROM timestamp) = EXTRACT(YEAR FROM NOW())`,
      [req.user.companyId]
    );

    // Top detection types
    const typesResult = await pool.query(
      `SELECT detection_type, COUNT(*) as count
       FROM detections
       WHERE company_id = $1
       GROUP BY detection_type
       ORDER BY count DESC
       LIMIT 5`,
      [req.user.companyId]
    );

    // Active users
    const usersResult = await pool.query(
      'SELECT COUNT(*) as total FROM users WHERE company_id = $1 AND active = true',
      [req.user.companyId]
    );

    res.json({
      totalDetections: parseInt(totalResult.rows[0].total),
      monthDetections: parseInt(monthResult.rows[0].total),
      topTypes: typesResult.rows,
      activeUsers: parseInt(usersResult.rows[0].total)
    });

  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ============================================
// STRIPE ENDPOINTS (manter existentes)
// ============================================

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_dummy');

app.post('/api/checkout', async (req, res) => {
  const { priceId, email, companyName } = req.body;
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: priceId,
        quantity: 1
      }],
      mode: 'subscription',
      success_url: 'https://aishield.eu/success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://aishield.eu/cancel',
      customer_email: email,
      metadata: { companyName }
    });
    
    res.json({ sessionId: session.id, url: session.url });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// EMAIL FUNCTIONS
// ============================================

async function sendWelcomeEmail(email, name, companyName) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.log('Email credentials not configured, skipping welcome email');
    return;
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h1 style="color: #002d5c;">Bem-vindo ao AI Shield! 🛡️</h1>
      
      <p>Olá ${name},</p>
      
      <p>Sua conta foi criada com sucesso! Você agora tem acesso ao AI Shield para proteger 
      ${companyName} contra vazamentos de dados em ferramentas de IA.</p>
      
      <h2 style="color: #00a8e8;">Próximos Passos:</h2>
      
      <ol>
        <li><strong>Instale a extensão Chrome</strong>
          <br>Acesse: <a href="https://chrome.google.com/webstore">Chrome Web Store</a>
          <br>Busque: "AI Shield"
        </li>
        
        <li><strong>Configure sua equipe</strong>
          <br>Adicione colaboradores no dashboard
        </li>
        
        <li><strong>Teste a proteção</strong>
          <br>Abra ChatGPT e tente colar um CPF ou email
          <br>Você verá o alerta de proteção!
        </li>
      </ol>
      
      <h3>Trial de 14 dias ativo! ✅</h3>
      <p>Você tem acesso completo a todas as funcionalidades por 14 dias, sem necessidade de cartão de crédito.</p>
      
      <div style="background: #f0f9ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 0;"><strong>Precisa de ajuda?</strong></p>
        <p style="margin: 10px 0 0 0;">Responda este email ou entre em contato: support@aishield.eu</p>
      </div>
      
      <p>Obrigado por escolher o AI Shield!</p>
      
      <p>Equipe AI Shield<br>
      <a href="https://aishield.eu">aishield.eu</a></p>
    </div>
  `;
  
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: '🛡️ Bem-vindo ao AI Shield - Sua conta está ativa!',
      html: html
    });
    
    console.log(`Welcome email sent to ${email}`);
  } catch (error) {
    console.error('Error sending welcome email:', error);
  }
}
// Dashboard Statistics
app.get('/api/dashboard/stats/:companyId', authenticateToken, async (req, res) => {
  const { companyId } = req.params;
  
  try {
    // Total detections all time
    const totalResult = await pool.query(
      'SELECT COUNT(*) as total FROM detections WHERE company_id = $1',
      [companyId]
    );
    
    // Monthly detections (last 30 days)
    const monthlyResult = await pool.query(
      `SELECT COUNT(*) as monthly FROM detections 
       WHERE company_id = $1 
       AND timestamp > NOW() - INTERVAL '30 days'`,
      [companyId]
    );
    
    // Active users (distinct users who triggered detections)
    const usersResult = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as users FROM detections WHERE company_id = $1',
      [companyId]
    );
    
    const totalDetections = parseInt(totalResult.rows[0].total) || 0;
    const monthlyDetections = parseInt(monthlyResult.rows[0].monthly) || 0;
    const activeUsers = parseInt(usersResult.rows[0].users) || 1;
    
    res.json({
      totalDetections,
      monthlyDetections,
      activeUsers,
      finesPrevented: totalDetections * 50000
    });
    
  } catch (error) {
    console.error('Error loading dashboard stats:', error);
    res.status(500).json({ error: 'Failed to load statistics' });
  }
});
// ===============================
// COMPANY UPDATE
// ===============================
app.put('/api/company/:companyId', authenticateToken, async (req, res) => {
  const { companyId } = req.params;
  const { name, admin_email, industry } = req.body;
  
  try {
    await pool.query(
      'UPDATE companies SET name = $1, admin_email = $2, industry = $3 WHERE id = $4',
      [name, admin_email, industry, companyId]
    );
    
    res.json({ success: true, message: 'Company updated' });
  } catch (error) {
    console.error('Error updating company:', error);
    res.status(500).json({ error: 'Failed to update company' });
  }
});

// ===============================
// SETTINGS UPDATE
// ===============================
app.put('/api/settings/:companyId', authenticateToken, async (req, res) => {
  const { companyId } = req.params;
  const { alert_critical, email_notifications, weekly_digest } = req.body;
  
  try {
    // Criar tabela settings se não existir
    await pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        company_id UUID PRIMARY KEY REFERENCES companies(id),
        alert_critical BOOLEAN DEFAULT true,
        email_notifications BOOLEAN DEFAULT true,
        weekly_digest BOOLEAN DEFAULT true,
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    
    // Inserir ou atualizar settings
    await pool.query(`
      INSERT INTO settings (company_id, alert_critical, email_notifications, weekly_digest)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (company_id)
      DO UPDATE SET
        alert_critical = COALESCE($2, settings.alert_critical),
        email_notifications = COALESCE($3, settings.email_notifications),
        weekly_digest = COALESCE($4, settings.weekly_digest),
        updated_at = NOW()
    `, [companyId, alert_critical, email_notifications, weekly_digest]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// ===============================
// GET SETTINGS
// ===============================
app.get('/api/settings/:companyId', authenticateToken, async (req, res) => {
  const { companyId } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT * FROM settings WHERE company_id = $1',
      [companyId]
    );
    
    if (result.rows.length === 0) {
      // Retornar defaults se não existir
      res.json({
        alert_critical: true,
        email_notifications: true,
        weekly_digest: true
      });
    } else {
      res.json(result.rows[0]);
    }
  } catch (error) {
    console.error('Error loading settings:', error);
    res.json({
      alert_critical: true,
      email_notifications: true,
      weekly_digest: true
    });
  }
});

// ===============================
// SUBSCRIPTION INFO
// ===============================
app.get('/api/subscription/:companyId', authenticateToken, async (req, res) => {
  const { companyId } = req.params;
  
  try {
    const company = await pool.query(
      'SELECT * FROM companies WHERE id = $1',
      [companyId]
    );
    
    if (company.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Por enquanto retornar hardcoded (integrar Stripe depois)
    const nextPayment = new Date();
    nextPayment.setMonth(nextPayment.getMonth() + 1);
    
    res.json({
      plan: company.rows[0].plan || 'Team',
      billing_cycle: 'Monthly',
      next_payment: nextPayment.toISOString().split('T')[0],
      payment_method: 'Coming soon'
    });
  } catch (error) {
    console.error('Error loading subscription:', error);
    res.status(500).json({ error: 'Failed to load subscription' });
  }
});
// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AI-Shield Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`JWT Authentication: ENABLED`);
});
