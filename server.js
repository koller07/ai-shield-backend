// ============================================
// IA SHIELD BACKEND - CORRIGIDO + ADMIN DASHBOARD
// By Koller Group
// ============================================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

dotenv.config();

const app = express();

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
     fs = require('fs');
     sql = fs.readFileSync('./init.sql', 'utf8');
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
   prefix = planType === 'enterprise' ? 'sk_ent' : 
                 planType === 'team' ? 'sk_team' : 'sk_solo';
  const randomString = crypto.randomBytes(32).toString('hex');
  return `${prefix}_${randomString}`;
}

// Mascarar dados sensíveis
function maskSensitiveData(value, type) {
  if (!value) return '';
  
  switch(type.toUpperCase()) {
    case 'CPF':
      // 123.456.789-00 → ***.***.789-**
      return value.replace(/(\d{3})\.(\d{3})\.(\d{3})-(\d{2})/, '***.**.$3-**');
    
    case 'CNPJ':
      // 12.345.678/0001-90 → **.***.***/****-**
      return value.replace(/(\d{2})\.(\d{3})\.(\d{3})\/(\d{4})-(\d{2})/, '**.***.***/$4-**');
    
    case 'EMAIL':
      // joao@empresa.com → j***@empresa.com
      const [name, domain] = value.split('@');
      return `${name[0]}***@${domain}`;
    
    case 'CREDIT_CARD':
      // 4532 1234 5678 9010 → **** **** **** 9010
      return value.replace(/(\d{4})\s(\d{4})\s(\d{4})\s(\d{4})/, '**** **** **** $4');
    
    default:
      // Mostrar apenas últimos 4 caracteres
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
    
    // Adicionar dados da empresa no request
    req.company = result.rows[0];
    next();
  } catch (error) {
    console.error('Erro ao validar API Key:', error);
    res.status(500).json({ error: 'Erro ao validar autenticação' });
  }
}

// ============================================
// ENDPOINTS PÚBLICOS (SEM AUTENTICAÇÃO)
// ============================================

// 1. Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'IA Shield Backend rodando',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// 1.5. Inicializar banco de dados (TEMPORÁRIO - só para setup inicial)
app.get('/api/admin/init-database', async (req, res) => {
  const { adminPassword } = req.query;
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Senha de administrador inválida' });
  }
  
  try {
    console.log('🗄️ Inicializando banco de dados...');
    
    // Dropar tabelas antigas
    await pool.query('DROP TABLE IF EXISTS detections CASCADE');
    await pool.query('DROP TABLE IF EXISTS monthly_reports CASCADE');
    await pool.query('DROP TABLE IF EXISTS users CASCADE');
    await pool.query('DROP TABLE IF EXISTS companies CASCADE');
    console.log('✅ Tabelas antigas removidas');
    
    // Criar tabela companies
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
    
    // Criar tabela users
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
    
    // Criar tabela detections
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
    
    // Criar tabela monthly_reports
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
    
    // Criar índices
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

// 2. Criar empresa manualmente (para Plano Enterprise - Dashboard Koller)
app.post('/api/admin/companies', async (req, res) => {
  const { name, adminEmail, planType, maxUsers, adminPassword } = req.body;
  
  // Senha de admin (colocar no .env)
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
    
    // Enviar email com API Key
    await sendWelcomeEmail(adminEmail, name, apiKey, result.rows[0].id);
    
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

// 3. Registrar/Atualizar usuário
app.post('/api/users/register', authenticateApiKey, async (req, res) => {
  const { userName, userEmail } = req.body;
  const companyId = req.company.id;
  
  if (!userName || !userEmail) {
    return res.status(400).json({ error: 'Nome e email são obrigatórios' });
  }
  
  try {
    // Verificar limite de usuários
    const userCount = await pool.query(
      'SELECT COUNT(*) FROM users WHERE company_id = $1 AND is_active = true',
      [companyId]
    );
    
    if (parseInt(userCount.rows[0].count) >= req.company.max_users) {
      return res.status(403).json({ 
        error: `Limite de usuários atingido (${req.company.max_users} usuários no plano ${req.company.plan_type})` 
      });
    }
    
    // Inserir ou atualizar usuário
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

// 4. Registrar detecção (ROTA CORRIGIDA)
app.post('/api/detections', authenticateApiKey, async (req, res) => {
  const { userEmail, detectionType, confidenceLevel, aiPlatform, url, detectedValue } = req.body;
  const companyId = req.company.id;
  
  try {
    // Buscar ID do usuário
    const userResult = await pool.query(
      'SELECT id FROM users WHERE company_id = $1 AND user_email = $2',
      [companyId, userEmail]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado. Registre o usuário primeiro.' });
    }
    
    const userId = userResult.rows[0].id;
    const maskedValue = maskSensitiveData(detectedValue, detectionType);
    
    // Inserir detecção
    await pool.query(
      `INSERT INTO detections 
       (company_id, user_id, detection_type, confidence_level, ai_platform, url, detected_value_masked, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [companyId, userId, detectionType, confidenceLevel, aiPlatform, url, maskedValue, new Date()]
    );
    
    // Atualizar última atividade do usuário
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

// 5. Buscar detecções da empresa
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
    
    // Filtrar por usuário específico se fornecido
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

// 6. Estatísticas da empresa
app.get('/api/stats', authenticateApiKey, async (req, res) => {
  const companyId = req.company.id;
  
  try {
    const result = await pool.query(
      'SELECT * FROM company_statistics WHERE company_id = $1',
      [companyId]
    );
    
    res.json({
      success: true,
      stats: result.rows[0] || {
        total_users: 0,
        active_users: 0,
        total_detections: 0,
        confirmed_detections: 0,
        suspicious_detections: 0
      }
    });
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// 7. Relatório mensal
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
        fine_prevented_eur: totalConfirmed * 50000 // €50k por detecção confirmada
      },
      users: result.rows
    });
  } catch (error) {
    console.error('Erro ao gerar relatório:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// 8. Listar usuários da empresa
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
// STRIPE WEBHOOKS E CHECKOUT
// ============================================

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_dummy');

// Criar sessão de checkout
app.post('/api/checkout', async (req, res) => {
  const { priceId, email, companyName, planType } = req.body;
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL || 'https://aishield.eu'}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL || 'https://aishield.eu'}/cancel`,
      customer_email: email,
      metadata: { companyName, planType }
    });
    
    res.json({ sessionId: session.id, url: session.url });
  } catch (error) {
    console.error('Erro no checkout:', error);
    res.status(500).json({ error: error.message });
  }
});

// Webhook do Stripe
app.post('/api/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  try {
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_dummy'
    );
    
    // Assinatura criada
    if (event.type === 'customer.subscription.created') {
      const subscription = event.data.object;
      const customer = await stripe.customers.retrieve(subscription.customer);
      
      const planType = subscription.metadata?.planType || 'team';
      const maxUsers = planType === 'solo' ? 1 : planType === 'team' ? 10 : 999999;
      const apiKey = generateApiKey(planType);
      
      const result = await pool.query(
        `INSERT INTO companies 
         (name, admin_email, plan_type, max_users, stripe_customer_id, stripe_subscription_id, api_key, subscription_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [
          customer.metadata?.companyName || customer.email,
          customer.email,
          planType,
          maxUsers,
          subscription.customer,
          subscription.id,
          apiKey,
          subscription.status
        ]
      );
      
      // Enviar email de boas-vindas
      await sendWelcomeEmail(customer.email, result.rows[0].name, apiKey, result.rows[0].id);
      
      console.log('✅ Nova assinatura criada:', subscription.id);
    }
    
    // Assinatura cancelada
    if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object;
      await pool.query(
        'UPDATE companies SET is_active = false, subscription_status = $1 WHERE stripe_subscription_id = $2',
        ['canceled', subscription.id]
      );
      console.log('⚠️ Assinatura cancelada:', subscription.id);
    }
    
    res.json({received: true});
  } catch (error) {
    console.error('Erro no webhook:', error);
    res.status(400).send(`Webhook Error: ${error.message}`);
  }
});

// ============================================
// DASHBOARD KOLLER GROUP (ADMIN) - ROTAS COMPLETAS
// ============================================

// Listar todas as empresas (com contadores)
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

// Listar todos os usuários (admin)
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

// Listar todas as detecções (admin com filtros)
app.get('/api/admin/detections', async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const { limit = 100, offset = 0, dateFrom, dateTo, confidence, type, companyId } = req.query;
    
    let whereConditions = [];
    let params = [];
    let paramCount = 1;
    
    if (dateFrom) {
      whereConditions.push(`d.timestamp >= $${paramCount}`);
      params.push(dateFrom);
      paramCount++;
    }
    
    if (dateTo) {
      whereConditions.push(`d.timestamp <= $${paramCount}`);
      params.push(dateTo);
      paramCount++;
    }
    
    if (confidence) {
      whereConditions.push(`d.confidence_level = $${paramCount}`);
      params.push(confidence);
      paramCount++;
    }
    
    if (type) {
      whereConditions.push(`d.detection_type = $${paramCount}`);
      params.push(type);
      paramCount++;
    }
    
    if (companyId) {
      whereConditions.push(`d.company_id = $${paramCount}`);
      params.push(companyId);
      paramCount++;
    }
    
    const whereClause = whereConditions.length > 0 
      ? 'WHERE ' + whereConditions.join(' AND ')
      : '';
    
    params.push(limit, offset);
    
    const result = await pool.query(`
      SELECT 
        d.id,
        d.detection_type,
        d.confidence_level,
        d.ai_platform,
        d.url,
        d.detected_value_masked,
        d.timestamp,
        d.created_at,
        u.user_name,
        u.user_email,
        c.name as company_name
      FROM detections d
      JOIN users u ON d.user_id = u.id
      JOIN companies c ON d.company_id = c.id
      ${whereClause}
      ORDER BY d.timestamp DESC
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, params);
    
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
    // Total de empresas
    const companiesResult = await pool.query(
      'SELECT COUNT(*) as total FROM companies WHERE is_active = true'
    );
    const totalCompanies = parseInt(companiesResult.rows[0].total);
    
    // Total de usuários
    const usersResult = await pool.query(
      'SELECT COUNT(*) as total FROM users WHERE is_active = true'
    );
    const totalUsers = parseInt(usersResult.rows[0].total);
    
    // Total de detecções
    const detectionsResult = await pool.query(
      'SELECT COUNT(*) as total FROM detections'
    );
    const totalDetections = parseInt(detectionsResult.rows[0].total);
    
    // Detecções do mês
    const monthResult = await pool.query(`
      SELECT COUNT(*) as total 
      FROM detections 
      WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE)
    `);
    const monthDetections = parseInt(monthResult.rows[0].total);
    
    // Confirmadas vs Suspeitas
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
      totalCompanies,
      totalUsers,
      totalDetections,
      monthDetections,
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

async function sendWelcomeEmail(email, companyName, apiKey, companyId) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  const html = `
    <h1>Bem-vindo ao IA Shield!</h1>
    <p>Olá ${companyName},</p>
    <p>Sua conta foi criada com sucesso. Aqui estão suas credenciais:</p>
    
    <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
      <p><strong>Company ID:</strong> ${companyId}</p>
      <p><strong>API Key:</strong> <code style="background: white; padding: 4px 8px; border-radius: 4px;">${apiKey}</code></p>
    </div>
    
    <h3>Como usar:</h3>
    <ol>
      <li>Instale a extensão IA Shield no Chrome</li>
      <li>Clique no ícone da extensão</li>
      <li>Cole seu Company ID e API Key</li>
      <li>Pronto! Você está protegido.</li>
    </ol>
    
    <p><strong>IMPORTANTE:</strong> Guarde sua API Key em local seguro. Não compartilhe publicamente.</p>
    
    <p>Equipe IA Shield - Koller Group</p>
  `;
  
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: '🛡️ Bem-vindo ao IA Shield - Suas Credenciais',
      html
    });
    console.log(`✅ Email enviado para ${email}`);
  } catch (error) {
    console.error('❌ Erro ao enviar email:', error);
  }
}

// Enviar relatórios mensais (todo dia 1 às 8h)
schedule.scheduleJob('0 8 1 * *', async () => {
  console.log('📧 Enviando relatórios mensais...');
  
  try {
    const companies = await pool.query('SELECT * FROM companies WHERE is_active = true');
    
    for (const company of companies.rows) {
      const now = new Date();
      const lastMonth = now.getMonth() === 0 ? 12 : now.getMonth();
      const lastYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
      
      // Buscar dados do relatório
      const reportData = await pool.query(
        `SELECT 
          u.user_name,
          u.user_email,
          COUNT(CASE WHEN d.confidence_level = 'confirmed' THEN 1 END) as confirmed,
          COUNT(CASE WHEN d.confidence_level = 'suspicious' THEN 1 END) as suspicious
        FROM users u
        LEFT JOIN detections d ON u.id = d.user_id 
          AND EXTRACT(MONTH FROM d.timestamp) = $1 
          AND EXTRACT(YEAR FROM d.timestamp) = $2
        WHERE u.company_id = $3 AND u.is_active = true
        GROUP BY u.user_name, u.user_email`,
        [lastMonth, lastYear, company.id]
      );
      
      await sendMonthlyReport(company, lastMonth, lastYear, reportData.rows);
    }
  } catch (error) {
    console.error('❌ Erro ao enviar relatórios:', error);
  }
});

async function sendMonthlyReport(company, month, year, userData) {
  const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  const monthName = new Date(year, month - 1).toLocaleString('pt-PT', { month: 'long' });
  const totalConfirmed = userData.reduce((sum, u) => sum + parseInt(u.confirmed), 0);
  const totalSuspicious = userData.reduce((sum, u) => sum + parseInt(u.suspicious), 0);
  
  let userRows = userData.map(u => `
    <tr>
      <td style="padding: 8px; border: 1px solid #ddd;">${u.user_name}</td>
      <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">${u.confirmed}</td>
      <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">${u.suspicious}</td>
    </tr>
  `).join('');
  
  const html = `
    <h1>🛡️ IA Shield - Relatório Mensal</h1>
    <p>Olá ${company.name},</p>
    <p>Aqui está o relatório de <strong>${monthName} ${year}</strong>:</p>
    
    <h2>📊 Resumo</h2>
    <ul>
      <li>🔴 <strong>Detecções Confirmadas:</strong> ${totalConfirmed}</li>
      <li>🟡 <strong>Suspeitas:</strong> ${totalSuspicious}</li>
      <li>💰 <strong>Multas Prevenidas:</strong> €${(totalConfirmed * 50000).toLocaleString()}</li>
    </ul>
    
    <h2>👥 Por Funcionário</h2>
    <table style="border-collapse: collapse; width: 100%;">
      <tr style="background: #f5f5f5;">
        <th style="padding: 8px; border: 1px solid #ddd;">Funcionário</th>
        <th style="padding: 8px; border: 1px solid #ddd;">Confirmadas</th>
        <th style="padding: 8px; border: 1px solid #ddd;">Suspeitas</th>
      </tr>
      ${userRows}
    </table>
    
    <p style="margin-top: 20px;">Continue protegido!</p>
    <p>Equipe IA Shield - Koller Group</p>
  `;
  
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: company.admin_email,
      subject: `📊 IA Shield - Relatório ${monthName} ${year}`,
      html
    });
    console.log(`✅ Relatório enviado para ${company.admin_email}`);
  } catch (error) {
    console.error('❌ Erro ao enviar relatório:', error);
  }
}

// ============================================
// STRIPE CHECKOUT - Criar sessão de pagamento
// ============================================
app.post('/api/checkout', async (req, res) => {
  const { priceId, planType, email, companyName } = req.body;
  
  // Validação
  if (!priceId || !email || !companyName) {
    return res.status(400).json({ 
      error: 'Campos obrigatórios: priceId, email, companyName' 
    });
  }
  
  try {
    console.log(`📝 Criando checkout session para ${email}...`);
    
    // Criar sessão de checkout no Stripe
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1
        }
      ],
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

// ============================================
// STRIPE WEBHOOK - Receber eventos do Stripe
// ============================================
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  let event;
  
  try {
    // Verificar assinatura do webhook
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
  
  // Processar diferentes tipos de eventos
  try {
    switch (event.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(event.data.object);
        break;
        
      case 'customer.subscription.created':
        await handleSubscriptionCreated(event.data.object);
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

// ============================================
// FUNÇÕES DE PROCESSAMENTO DE EVENTOS STRIPE
// ============================================

// Checkout completado (pagamento aprovado)
async function handleCheckoutCompleted(session) {
  console.log(`✅ Checkout completado: ${session.id}`);
  
  const { customer_email, metadata, subscription } = session;
  const { companyName, planType } = metadata;
  
  // Buscar subscription para pegar informações completas
  const stripeSubscription = await stripe.subscriptions.retrieve(subscription);
  
  // Gerar API Key única
  const apiKey = generateApiKey(planType);
  
  // Determinar número máximo de usuários
  const maxUsers = planType === 'solo' ? 1 : 
                   planType === 'team' ? 10 : 
                   999999; // enterprise
  
  try {
    // Criar empresa no banco de dados
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
    
    const company = companyResult.rows[0];
    console.log(`✅ Empresa criada: ${company.id}`);
    
    // Enviar email de boas-vindas com API Key
    await sendWelcomeEmail(customer_email, companyName, apiKey, planType);
    
    console.log(`✅ Email de boas-vindas enviado para ${customer_email}`);
    
  } catch (error) {
    console.error('❌ Erro ao criar empresa:', error);
    throw error;
  }
}

// Subscription criada
async function handleSubscriptionCreated(subscription) {
  console.log(`📝 Subscription criada: ${subscription.id}`);
  // Já tratado em checkout.session.completed
}

// Subscription atualizada (upgrade, downgrade, renovação)
async function handleSubscriptionUpdated(subscription) {
  console.log(`🔄 Subscription atualizada: ${subscription.id}`);
  
  try {
    // Atualizar status da empresa
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

// Subscription cancelada
async function handleSubscriptionDeleted(subscription) {
  console.log(`❌ Subscription cancelada: ${subscription.id}`);
  
  try {
    // Desativar empresa
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

// ============================================
// FUNÇÃO DE EMAIL DE BOAS-VINDAS
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
    throw error;
  }
}

// ============================================
// ROTA DE TESTE DO STRIPE (OPCIONAL)
// ============================================
app.get('/api/stripe/test', async (req, res) => {
  try {
    // Testar conexão com Stripe
    const products = await stripe.products.list({ limit: 3 });
    
    res.json({
      success: true,
      message: 'Stripe conectado!',
      products: products.data.map(p => ({ id: p.id, name: p.name })),
      testMode: process.env.STRIPE_SECRET_KEY.includes('test')
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============================================
// FIM DO CÓDIGO STRIPE
// Cole este código no seu server.js existente!
// ============================================

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   🛡️  IA SHIELD BACKEND v2.0.0        ║
  ║   By Koller Group                     ║
  ║   + Admin Dashboard Routes            ║
  ╚════════════════════════════════════════╝
  
  ✅ Servidor rodando na porta ${PORT}
  ✅ Ambiente: ${process.env.NODE_ENV || 'development'}
  ✅ Rotas Admin: /api/admin/*
  
  `);
});
