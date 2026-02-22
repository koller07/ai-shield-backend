// ============================================
// AI SHIELD BACKEND - VERSÃO CORRIGIDA
// By Koller Group
// ============================================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const crypto = require('crypto');
const fs = require('fs');

dotenv.config();

const app = express();

// Stripe (UMA VEZ SÓ!)
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_dummy');

// Middleware especial para webhook do Stripe (precisa vir ANTES do express.json())
app.use('/api/webhook', express.raw({type: 'application/json'}));

// Middleware padrão
app.use(express.json());
app.use(cors());

// ============================================
// CONEXÃO COM BANCO DE DADOS
// ============================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Testar conexão
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Erro ao conectar banco de dados:', err);
  } else {
    console.log('✅ Banco de dados conectado:', res.rows[0].now);
  }
});

// Inicializar tabelas
async function initializeDatabase() {
  try {
    const sql = fs.readFileSync('./init.sql', 'utf8');
    await pool.query(sql);
    console.log('✅ Tabelas do banco de dados inicializadas');
  } catch (error) {
    console.error('❌ Erro ao inicializar banco:', error);
  }
}

initializeDatabase();

// ============================================
// FUNÇÕES AUXILIARES
// ============================================

// Gerar API Key única
function generateApiKey(planType) {
  const prefix = planType === 'enterprise' ? 'sk_ent' : 
                 planType === 'team' ? 'sk_team' : 'sk_solo';
  const randomString = crypto.randomBytes(32).toString('hex');
  return `${prefix}_${randomString}`;
}

// Mascarar dados sensíveis
function maskSensitiveData(value, type) {
  if (!value) return '';
  
  switch(type.toUpperCase()) {
    case 'CPF':
      return value.replace(/(\d{3})\.(\d{3})\.(\d{3})-(\d{2})/, '***.**.$3-**');
    case 'CNPJ':
      return value.replace(/(\d{2})\.(\d{3})\.(\d{3})\/(\d{4})-(\d{2})/, '**.***.***/$4-**');
    case 'EMAIL':
      const [name, domain] = value.split('@');
      return `${name[0]}***@${domain}`;
    case 'CREDIT_CARD':
      return value.replace(/(\d{4})\s(\d{4})\s(\d{4})\s(\d{4})/, '**** **** **** $4');
    default:
      return '***' + value.slice(-4);
  }
}

// Middleware de autenticação por API Key
async function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API Key não fornecida' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM companies WHERE api_key = $1 AND is_active = true',
      [apiKey]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'API Key inválida ou empresa inativa' });
    }
    
    req.company = result.rows[0];
    next();
  } catch (error) {
    console.error('Erro ao validar API Key:', error);
    res.status(500).json({ error: 'Erro ao validar autenticação' });
  }
}

// ============================================
// ENDPOINTS PÚBLICOS
// ============================================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'AI Shield Backend rodando',
    version: '3.0.0',
    timestamp: new Date().toISOString()
  });
});

// Inicializar banco de dados
app.get('/api/admin/init-database', async (req, res) => {
  const { adminPassword } = req.query;
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Senha de administrador inválida' });
  }
  
  try {
    console.log('🗄️ Inicializando banco de dados...');
    
    await pool.query('DROP TABLE IF EXISTS detections CASCADE');
    await pool.query('DROP TABLE IF EXISTS monthly_reports CASCADE');
    await pool.query('DROP TABLE IF EXISTS users CASCADE');
    await pool.query('DROP TABLE IF EXISTS companies CASCADE');
    console.log('✅ Tabelas antigas removidas');
    
    await pool.query(`
      CREATE TABLE companies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        admin_email VARCHAR(255) NOT NULL UNIQUE,
        plan_type VARCHAR(50) NOT NULL CHECK (plan_type IN ('solo', 'team', 'enterprise')),
        max_users INTEGER NOT NULL DEFAULT 1,
        stripe_customer_id VARCHAR(255) UNIQUE,
        stripe_subscription_id VARCHAR(255) UNIQUE,
        api_key VARCHAR(255) NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT true,
        subscription_status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        subscription_end_date TIMESTAMP
      )
    `);
    console.log('✅ Tabela companies criada');
    
    await pool.query(`
      CREATE TABLE users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        user_name VARCHAR(255) NOT NULL,
        user_email VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        last_activity TIMESTAMP,
        UNIQUE(company_id, user_email)
      )
    `);
    console.log('✅ Tabela users criada');
    
    await pool.query(`
      CREATE TABLE detections (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        detection_type VARCHAR(100) NOT NULL,
        confidence_level VARCHAR(20) NOT NULL CHECK (confidence_level IN ('confirmed', 'suspicious')),
        ai_platform VARCHAR(100),
        url TEXT,
        detected_value_masked VARCHAR(255),
        timestamp TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Tabela detections criada');
    
    await pool.query(`
      CREATE TABLE monthly_reports (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
        year INTEGER NOT NULL CHECK (year >= 2024),
        total_detections_confirmed INTEGER DEFAULT 0,
        total_detections_suspicious INTEGER DEFAULT 0,
        total_users_active INTEGER DEFAULT 0,
        report_data JSONB,
        generated_at TIMESTAMP DEFAULT NOW(),
        sent_at TIMESTAMP,
        UNIQUE(company_id, month, year)
      )
    `);
    console.log('✅ Tabela monthly_reports criada');
    
    await pool.query('CREATE INDEX idx_detections_company ON detections(company_id)');
    await pool.query('CREATE INDEX idx_detections_user ON detections(user_id)');
    await pool.query('CREATE INDEX idx_detections_timestamp ON detections(timestamp)');
    await pool.query('CREATE INDEX idx_detections_confidence ON detections(confidence_level)');
    await pool.query('CREATE INDEX idx_users_company ON users(company_id)');
    await pool.query('CREATE INDEX idx_companies_api_key ON companies(api_key)');
    console.log('✅ Índices criados');
    
    res.json({
      success: true,
      message: 'Banco de dados inicializado com sucesso!',
      tables_created: ['companies', 'users', 'detections', 'monthly_reports'],
      indexes_created: 6
    });
    
  } catch (error) {
    console.error('❌ Erro ao inicializar banco:', error);
    res.status(500).json({ 
      error: 'Erro ao inicializar banco de dados',
      details: error.message 
    });
  }
});

// Criar empresa manualmente (admin)
app.post('/api/admin/companies', async (req, res) => {
  const { name, adminEmail, planType, maxUsers, adminPassword } = req.body;
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Senha de administrador inválida' });
  }
  
  try {
    const apiKey = generateApiKey(planType);
    
    const result = await pool.query(
      `INSERT INTO companies (name, admin_email, plan_type, max_users, api_key) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, adminEmail, planType, maxUsers || (planType === 'solo' ? 1 : planType === 'team' ? 10 : 999999), apiKey]
    );
    
    await sendWelcomeEmail(adminEmail, name, apiKey, planType);
    
    res.json({ 
      success: true,
      company: result.rows[0],
      message: 'Empresa criada com sucesso. Email enviado com instruções.'
    });
  } catch (error) {
    console.error('Erro ao criar empresa:', error);
    res.status(500).json({ error: 'Erro ao criar empresa' });
  }
});

// ============================================
// ENDPOINTS PROTEGIDOS (REQUER API KEY)
// ============================================

// Registrar usuário
app.post('/api/users/register', authenticateApiKey, async (req, res) => {
  const { userName, userEmail } = req.body;
  const companyId = req.company.id;
  
  if (!userName || !userEmail) {
    return res.status(400).json({ error: 'Nome e email são obrigatórios' });
  }
  
  try {
    const userCount = await pool.query(
      'SELECT COUNT(*) FROM users WHERE company_id = $1 AND is_active = true',
      [companyId]
    );
    
    if (parseInt(userCount.rows[0].count) >= req.company.max_users) {
      return res.status(403).json({ 
        error: `Limite de usuários atingido (${req.company.max_users} usuários no plano ${req.company.plan_type})` 
      });
    }
    
    const result = await pool.query(
      `INSERT INTO users (company_id, user_name, user_email, last_activity)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (company_id, user_email) 
       DO UPDATE SET user_name = $2, last_activity = NOW(), is_active = true
       RETURNING *`,
      [companyId, userName, userEmail]
    );
    
    res.json({ 
      success: true,
      user: result.rows[0],
      message: 'Usuário registrado com sucesso'
    });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

// Registrar detecção
app.post('/api/detections', authenticateApiKey, async (req, res) => {
  const { userEmail, detectionType, confidenceLevel, aiPlatform, url, detectedValue } = req.body;
  const companyId = req.company.id;
  
  try {
    const userResult = await pool.query(
      'SELECT id FROM users WHERE company_id = $1 AND user_email = $2',
      [companyId, userEmail]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado. Registre o usuário primeiro.' });
    }
    
    const userId = userResult.rows[0].id;
    const maskedValue = maskSensitiveData(detectedValue, detectionType);
    
    await pool.query(
      `INSERT INTO detections 
       (company_id, user_id, detection_type, confidence_level, ai_platform, url, detected_value_masked, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [companyId, userId, detectionType, confidenceLevel, aiPlatform, url, maskedValue, new Date()]
    );
    
    await pool.query(
      'UPDATE users SET last_activity = NOW() WHERE id = $1',
      [userId]
    );
    
    res.json({ success: true, message: 'Detecção registrada' });
  } catch (error) {
    console.error('Erro ao registrar detecção:', error);
    res.status(500).json({ error: 'Erro ao registrar detecção' });
  }
});

// Buscar detecções
app.get('/api/detections', authenticateApiKey, async (req, res) => {
  const companyId = req.company.id;
  const { limit = 100, userEmail } = req.query;
  
  try {
    let query = `
      SELECT 
        d.id,
        d.detection_type,
        d.confidence_level,
        d.ai_platform,
        d.url,
        d.detected_value_masked,
        d.timestamp,
        u.user_name,
        u.user_email
      FROM detections d
      JOIN users u ON d.user_id = u.id
      WHERE d.company_id = $1
    `;
    
    const params = [companyId];
    
    if (userEmail) {
      query += ' AND u.user_email = $2';
      params.push(userEmail);
    }
    
    query += ' ORDER BY d.timestamp DESC LIMIT $' + (params.length + 1);
    params.push(limit);
    
    const result = await pool.query(query, params);
    
    res.json({
      success: true,
      total: result.rows.length,
      detections: result.rows
    });
  } catch (error) {
    console.error('Erro ao buscar detecções:', error);
    res.status(500).json({ error: 'Erro ao buscar detecções' });
  }
});

// Estatísticas da empresa
app.get('/api/stats', authenticateApiKey, async (req, res) => {
  const companyId = req.company.id;
  
  try {
    const usersResult = await pool.query(
      'SELECT COUNT(*) as total FROM users WHERE company_id = $1 AND is_active = true',
      [companyId]
    );
    
    const detectionsResult = await pool.query(
      'SELECT COUNT(*) as total, confidence_level FROM detections WHERE company_id = $1 GROUP BY confidence_level',
      [companyId]
    );
    
    const confirmed = detectionsResult.rows.find(r => r.confidence_level === 'confirmed')?.total || 0;
    const suspicious = detectionsResult.rows.find(r => r.confidence_level === 'suspicious')?.total || 0;
    
    res.json({
      success: true,
      stats: {
        total_users: parseInt(usersResult.rows[0].total),
        total_detections: parseInt(confirmed) + parseInt(suspicious),
        confirmed_detections: parseInt(confirmed),
        suspicious_detections: parseInt(suspicious)
      }
    });
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// Relatório mensal
app.get('/api/report/:month/:year', authenticateApiKey, async (req, res) => {
  const { month, year } = req.params;
  const companyId = req.company.id;
  
  try {
    const result = await pool.query(
      `SELECT 
        u.user_name,
        u.user_email,
        COUNT(CASE WHEN d.confidence_level = 'confirmed' THEN 1 END) as confirmed_count,
        COUNT(CASE WHEN d.confidence_level = 'suspicious' THEN 1 END) as suspicious_count,
        COUNT(*) as total_count
      FROM users u
      LEFT JOIN detections d ON u.id = d.user_id 
        AND EXTRACT(MONTH FROM d.timestamp) = $1 
        AND EXTRACT(YEAR FROM d.timestamp) = $2
      WHERE u.company_id = $3 AND u.is_active = true
      GROUP BY u.user_name, u.user_email
      ORDER BY total_count DESC`,
      [month, year, companyId]
    );
    
    const totalConfirmed = result.rows.reduce((sum, row) => sum + parseInt(row.confirmed_count), 0);
    const totalSuspicious = result.rows.reduce((sum, row) => sum + parseInt(row.suspicious_count), 0);
    
    res.json({
      company: req.company.name,
      month: parseInt(month),
      year: parseInt(year),
      summary: {
        total_confirmed: totalConfirmed,
        total_suspicious: totalSuspicious,
        total_detections: totalConfirmed + totalSuspicious,
        fine_prevented_eur: totalConfirmed * 50000
      },
      users: result.rows
    });
  } catch (error) {
    console.error('Erro ao gerar relatório:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// Listar usuários
app.get('/api/users', authenticateApiKey, async (req, res) => {
  const companyId = req.company.id;
  
  try {
    const result = await pool.query(
      'SELECT id, user_name, user_email, is_active, created_at, last_activity FROM users WHERE company_id = $1',
      [companyId]
    );
    
    res.json({
      success: true,
      total: result.rows.length,
      max_users: req.company.max_users,
      users: result.rows
    });
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// ============================================
// STRIPE - CHECKOUT E WEBHOOK
// ============================================

// Criar sessão de checkout
app.post('/api/checkout', async (req, res) => {
  const { priceId, planType, email, companyName } = req.body;
  
  if (!priceId || !email || !companyName) {
    return res.status(400).json({ 
      error: 'Campos obrigatórios: priceId, email, companyName' 
    });
  }
  
  try {
    console.log(`📝 Criando checkout session para ${email}...`);
    
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: priceId,
        quantity: 1
      }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/#pricing`,
      customer_email: email,
      metadata: {
        companyName: companyName,
        planType: planType || 'team',
        source: 'ai-shield-website'
      },
      subscription_data: {
        metadata: {
          companyName: companyName,
          planType: planType || 'team'
        }
      }
    });
    
    console.log(`✅ Checkout session criada: ${session.id}`);
    
    res.json({ 
      sessionId: session.id,
      url: session.url 
    });
    
  } catch (error) {
    console.error('❌ Erro ao criar checkout session:', error);
    res.status(500).json({ 
      error: 'Erro ao criar sessão de checkout',
      details: error.message 
    });
  }
});

// Webhook do Stripe
app.post('/api/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  console.log(`📨 Webhook recebido: ${event.type}`);
  
  try {
    switch (event.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(event.data.object);
        break;
        
      case 'customer.subscription.created':
        console.log(`📝 Subscription criada: ${event.data.object.id}`);
        break;
        
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(event.data.object);
        break;
        
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(event.data.object);
        break;
        
      default:
        console.log(`⚠️ Evento não tratado: ${event.type}`);
    }
    
    res.json({ received: true });
    
  } catch (error) {
    console.error('❌ Erro ao processar webhook:', error);
    res.status(500).json({ error: 'Erro ao processar evento' });
  }
});

// Handlers de eventos Stripe
async function handleCheckoutCompleted(session) {
  console.log(`✅ Checkout completado: ${session.id}`);
  
  const { customer_email, metadata, subscription } = session;
  const { companyName, planType } = metadata;
  
  const stripeSubscription = await stripe.subscriptions.retrieve(subscription);
  const apiKey = generateApiKey(planType);
  const maxUsers = planType === 'solo' ? 1 : planType === 'team' ? 10 : 999999;
  
  try {
    const companyResult = await pool.query(
      `INSERT INTO companies 
       (name, admin_email, plan_type, max_users, api_key, 
        stripe_customer_id, stripe_subscription_id, is_active, subscription_status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
       RETURNING *`,
      [
        companyName,
        customer_email,
        planType,
        maxUsers,
        apiKey,
        stripeSubscription.customer,
        stripeSubscription.id,
        true,
        'active'
      ]
    );
    
    console.log(`✅ Empresa criada: ${companyResult.rows[0].id}`);
    
    await sendWelcomeEmail(customer_email, companyName, apiKey, planType);
    
    console.log(`✅ Email de boas-vindas enviado para ${customer_email}`);
    
  } catch (error) {
    console.error('❌ Erro ao criar empresa:', error);
    throw error;
  }
}

async function handleSubscriptionUpdated(subscription) {
  console.log(`🔄 Subscription atualizada: ${subscription.id}`);
  
  try {
    await pool.query(
      `UPDATE companies 
       SET subscription_status = $1, updated_at = NOW()
       WHERE stripe_subscription_id = $2`,
      [subscription.status, subscription.id]
    );
    
    console.log(`✅ Status atualizado para: ${subscription.status}`);
    
  } catch (error) {
    console.error('❌ Erro ao atualizar subscription:', error);
  }
}

async function handleSubscriptionDeleted(subscription) {
  console.log(`❌ Subscription cancelada: ${subscription.id}`);
  
  try {
    await pool.query(
      `UPDATE companies 
       SET is_active = false, subscription_status = 'canceled', updated_at = NOW()
       WHERE stripe_subscription_id = $1`,
      [subscription.id]
    );
    
    console.log(`✅ Empresa desativada`);
    
  } catch (error) {
    console.error('❌ Erro ao cancelar subscription:', error);
  }
}

// Teste Stripe
app.get('/api/stripe/test', async (req, res) => {
  try {
    const products = await stripe.products.list({ limit: 3 });
    
    res.json({
      success: true,
      message: 'Stripe conectado!',
      products: products.data.map(p => ({ id: p.id, name: p.name })),
      testMode: process.env.STRIPE_SECRET_KEY?.includes('test') || false
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============================================
// DASHBOARD ADMIN (KOLLER GROUP)
// ============================================

// Listar empresas (admin)
app.get('/api/admin/companies', async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Senha de administrador inválida' });
  }
  
  try {
    const result = await pool.query(`
      SELECT 
        c.*,
        COUNT(DISTINCT u.id) as user_count,
        COUNT(d.id) as detection_count
      FROM companies c
      LEFT JOIN users u ON c.id = u.company_id AND u.is_active = true
      LEFT JOIN detections d ON c.id = d.company_id
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `);
    
    res.json({ success: true, companies: result.rows });
  } catch (error) {
    console.error('Erro ao listar empresas:', error);
    res.status(500).json({ error: 'Erro ao listar empresas' });
  }
});

// Listar usuários (admin)
app.get('/api/admin/users', async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const result = await pool.query(`
      SELECT 
        u.id,
        u.user_name,
        u.user_email,
        u.is_active,
        u.created_at,
        u.last_activity,
        c.name as company_name,
        c.plan_type,
        COUNT(d.id) as detection_count
      FROM users u
      JOIN companies c ON u.company_id = c.id
      LEFT JOIN detections d ON u.id = d.user_id
      GROUP BY u.id, c.name, c.plan_type
      ORDER BY u.created_at DESC
    `);
    
    res.json({ success: true, users: result.rows });
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// Listar detecções (admin com filtros)
app.get('/api/admin/detections', async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const { limit = 100, offset = 0 } = req.query;
    
    const result = await pool.query(`
      SELECT 
        d.id,
        d.detection_type,
        d.confidence_level,
        d.ai_platform,
        d.timestamp,
        u.user_name,
        u.user_email,
        c.name as company_name
      FROM detections d
      JOIN users u ON d.user_id = u.id
      JOIN companies c ON d.company_id = c.id
      ORDER BY d.timestamp DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    
    res.json({ success: true, detections: result.rows });
  } catch (error) {
    console.error('Erro ao listar detecções:', error);
    res.status(500).json({ error: 'Erro ao listar detecções' });
  }
});

// Estatísticas globais (admin)
app.get('/api/admin/stats', async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const companiesResult = await pool.query(
      'SELECT COUNT(*) as total FROM companies WHERE is_active = true'
    );
    
    const usersResult = await pool.query(
      'SELECT COUNT(*) as total FROM users WHERE is_active = true'
    );
    
    const detectionsResult = await pool.query(
      'SELECT COUNT(*) as total FROM detections'
    );
    
    const monthResult = await pool.query(`
      SELECT COUNT(*) as total 
      FROM detections 
      WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE)
    `);
    
    const confidenceResult = await pool.query(`
      SELECT 
        confidence_level,
        COUNT(*) as count
      FROM detections
      GROUP BY confidence_level
    `);
    
    const confirmed = confidenceResult.rows.find(r => r.confidence_level === 'confirmed')?.count || 0;
    const suspicious = confidenceResult.rows.find(r => r.confidence_level === 'suspicious')?.count || 0;
    
    res.json({
      success: true,
      totalCompanies: parseInt(companiesResult.rows[0].total),
      totalUsers: parseInt(usersResult.rows[0].total),
      totalDetections: parseInt(detectionsResult.rows[0].total),
      monthDetections: parseInt(monthResult.rows[0].total),
      confirmedDetections: parseInt(confirmed),
      suspiciousDetections: parseInt(suspicious)
    });
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// ============================================
// EMAIL
// ============================================

async function sendWelcomeEmail(email, companyName, apiKey, planType) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  const planNames = {
    solo: 'Solo (1 usuário)',
    team: 'Team (até 10 usuários)',
    enterprise: 'Enterprise (ilimitado)'
  };
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      background: linear-gradient(135deg, #001a3d 0%, #003d7a 100%);
      color: white;
      padding: 30px;
      text-align: center;
      border-radius: 8px 8px 0 0;
    }
    .content {
      background: #f8f9fa;
      padding: 30px;
      border-radius: 0 0 8px 8px;
    }
    .api-key-box {
      background: white;
      border: 2px solid #00a8e8;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
      font-family: 'Monaco', 'Courier New', monospace;
      word-break: break-all;
    }
    .steps {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
    }
    .step {
      margin: 15px 0;
      padding-left: 30px;
      position: relative;
    }
    .step::before {
      content: "✓";
      position: absolute;
      left: 0;
      color: #22c55e;
      font-weight: bold;
      font-size: 20px;
    }
    .button {
      display: inline-block;
      background: #00a8e8;
      color: white;
      padding: 12px 30px;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
      margin: 10px 0;
    }
    .footer {
      text-align: center;
      color: #666;
      font-size: 12px;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Bem-vindo ao AI Shield!</h1>
    <p>Sua conta está ativa e pronta para proteger seus dados</p>
  </div>
  
  <div class="content">
    <p>Olá <strong>${companyName}</strong>,</p>
    
    <p>Obrigado por escolher o AI Shield! Sua assinatura do plano <strong>${planNames[planType]}</strong> está ativa.</p>
    
    <h3>🔑 Sua API Key:</h3>
    <div class="api-key-box">
      ${apiKey}
    </div>
    <p><strong>⚠️ Importante:</strong> Guarde esta API Key em segurança. Você precisará dela para configurar a extensão.</p>
    
    <h3>📋 Próximos passos:</h3>
    <div class="steps">
      <div class="step">
        <strong>1. Instale a extensão:</strong><br>
        Vá para a Chrome Web Store e instale a extensão AI Shield
      </div>
      <div class="step">
        <strong>2. Configure a extensão:</strong><br>
        Clique no ícone da extensão e cole sua API Key
      </div>
      <div class="step">
        <strong>3. Proteja seus dados:</strong><br>
        A extensão começará a monitorar automaticamente
      </div>
    </div>
    
    <center>
      <a href="https://chrome.google.com/webstore" class="button">Instalar Extensão Agora</a>
    </center>
    
    <h3>📊 Acesse seu Dashboard:</h3>
    <p>Visualize detecções, gerencie sua equipe e exporte relatórios de compliance:</p>
    <center>
      <a href="https://ai-shield-backend-production.up.railway.app/company-dashboard.html" class="button">Acessar Dashboard</a>
    </center>
    
    <h3>💬 Precisa de ajuda?</h3>
    <p>Nossa equipe está aqui para ajudar:</p>
    <ul>
      <li>📧 Email: ${process.env.EMAIL_USER}</li>
      <li>📚 Documentação: em breve</li>
    </ul>
  </div>
  
  <div class="footer">
    <p>© 2026 AI Shield by Koller Group</p>
    <p>GDPR & EU AI Act Compliant | Enterprise Data Protection</p>
  </div>
</body>
</html>
  `;
  
  try {
    await transporter.sendMail({
      from: `"AI Shield" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '🛡️ Bem-vindo ao AI Shield - Sua API Key',
      html: html
    });
    
    console.log(`✅ Email enviado para ${email}`);
    
  } catch (error) {
    console.error('❌ Erro ao enviar email:', error);
  }
}

// Relatórios mensais automáticos
schedule.scheduleJob('0 8 1 * *', async () => {
  console.log('📧 Enviando relatórios mensais...');
  
  try {
    const companies = await pool.query('SELECT * FROM companies WHERE is_active = true');
    
    for (const company of companies.rows) {
      const now = new Date();
      const lastMonth = now.getMonth() === 0 ? 12 : now.getMonth();
      const lastYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
      
      console.log(`📊 Relatório mensal para ${company.name}`);
    }
  } catch (error) {
    console.error('❌ Erro ao enviar relatórios:', error);
  }
});

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   🛡️  AI SHIELD BACKEND v3.0.0        ║
  ║   By Koller Group                     ║
  ║   CORRIGIDO - SEM DUPLICAÇÕES         ║
  ╚════════════════════════════════════════╝
  
  ✅ Servidor rodando na porta ${PORT}
  ✅ Ambiente: ${process.env.NODE_ENV || 'development'}
  ✅ Stripe: ${process.env.STRIPE_SECRET_KEY ? 'Configurado' : 'Não configurado'}
  
  `);
});
