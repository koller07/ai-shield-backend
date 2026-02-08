-- ============================================
-- IA SHIELD - DATABASE SCHEMA
-- Sistema de detecção de dados sensíveis
-- By Koller Group
-- ============================================

-- TABELA 1: EMPRESAS (Clientes)
-- Armazena informações das empresas que assinam o serviço
CREATE TABLE IF NOT EXISTS companies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  admin_email VARCHAR(255) NOT NULL UNIQUE,
  
  -- Plano de assinatura
  plan_type VARCHAR(50) NOT NULL CHECK (plan_type IN ('solo', 'team', 'enterprise')),
  max_users INTEGER NOT NULL DEFAULT 1, -- Solo: 1, Team: 10, Enterprise: ilimitado
  
  -- Integração Stripe
  stripe_customer_id VARCHAR(255) UNIQUE,
  stripe_subscription_id VARCHAR(255) UNIQUE,
  
  -- API Key para autenticação
  api_key VARCHAR(255) NOT NULL UNIQUE,
  
  -- Status
  is_active BOOLEAN DEFAULT true,
  subscription_status VARCHAR(50) DEFAULT 'active', -- active, canceled, past_due
  
  -- Datas
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  subscription_end_date TIMESTAMP
);

-- TABELA 2: USUÁRIOS (Funcionários das empresas)
-- Armazena cada pessoa que usa a extensão
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  
  -- Identificação do usuário
  user_name VARCHAR(255) NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  
  -- Status
  is_active BOOLEAN DEFAULT true,
  
  -- Datas
  created_at TIMESTAMP DEFAULT NOW(),
  last_activity TIMESTAMP,
  
  -- Garantir que cada email seja único por empresa
  UNIQUE(company_id, user_email)
);

-- TABELA 3: DETECÇÕES (Dados sensíveis encontrados)
-- Armazena cada vez que a extensão detecta algo suspeito ou confirmado
CREATE TABLE IF NOT EXISTS detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Tipo de detecção
  detection_type VARCHAR(100) NOT NULL, -- CPF, CNPJ, EMAIL, CREDIT_CARD, etc
  
  -- Nível de confiança (NOVO - IMPORTANTE!)
  confidence_level VARCHAR(20) NOT NULL CHECK (confidence_level IN ('confirmed', 'suspicious')),
  -- confirmed = vermelho (certeza que é dado sensível)
  -- suspicious = amarelo (possível dado sensível)
  
  -- Plataforma onde foi detectado
  ai_platform VARCHAR(100), -- ChatGPT, Claude, Gemini, etc
  url TEXT, -- URL da página onde ocorreu
  
  -- Valor detectado (mascarado para segurança)
  detected_value_masked VARCHAR(255), -- Ex: "***.***.789-**"
  
  -- Data e hora
  timestamp TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- TABELA 4: RELATÓRIOS MENSAIS (Cache de relatórios)
-- Armazena relatórios pré-calculados para performance
CREATE TABLE IF NOT EXISTS monthly_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  
  -- Período do relatório
  month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
  year INTEGER NOT NULL CHECK (year >= 2024),
  
  -- Estatísticas gerais
  total_detections_confirmed INTEGER DEFAULT 0,
  total_detections_suspicious INTEGER DEFAULT 0,
  total_users_active INTEGER DEFAULT 0,
  
  -- Dados em JSON (detalhes por usuário)
  report_data JSONB,
  
  -- Controle
  generated_at TIMESTAMP DEFAULT NOW(),
  sent_at TIMESTAMP,
  
  -- Garantir um relatório por mês/ano por empresa
  UNIQUE(company_id, month, year)
);

-- ============================================
-- ÍNDICES PARA PERFORMANCE
-- ============================================

CREATE INDEX IF NOT EXISTS idx_detections_company ON detections(company_id);
CREATE INDEX IF NOT EXISTS idx_detections_user ON detections(user_id);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_type ON detections(detection_type);
CREATE INDEX IF NOT EXISTS idx_detections_confidence ON detections(confidence_level);
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
CREATE INDEX IF NOT EXISTS idx_companies_api_key ON companies(api_key);

-- ============================================
-- FUNÇÃO PARA ATUALIZAR updated_at
-- ============================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_companies_updated_at 
BEFORE UPDATE ON companies
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- VIEWS ÚTEIS PARA RELATÓRIOS
-- ============================================

-- View: Estatísticas por empresa
CREATE OR REPLACE VIEW company_statistics AS
SELECT 
  c.id as company_id,
  c.name as company_name,
  c.plan_type,
  COUNT(DISTINCT u.id) as total_users,
  COUNT(DISTINCT CASE WHEN u.is_active THEN u.id END) as active_users,
  COUNT(d.id) as total_detections,
  COUNT(CASE WHEN d.confidence_level = 'confirmed' THEN 1 END) as confirmed_detections,
  COUNT(CASE WHEN d.confidence_level = 'suspicious' THEN 1 END) as suspicious_detections
FROM companies c
LEFT JOIN users u ON c.id = u.company_id
LEFT JOIN detections d ON u.id = d.user_id
WHERE c.is_active = true
GROUP BY c.id, c.name, c.plan_type;

-- View: Atividade recente (últimas 24h)
CREATE OR REPLACE VIEW recent_activity AS
SELECT 
  c.name as company_name,
  u.user_name,
  u.user_email,
  d.detection_type,
  d.confidence_level,
  d.ai_platform,
  d.timestamp
FROM detections d
JOIN users u ON d.user_id = u.id
JOIN companies c ON d.company_id = c.id
WHERE d.timestamp > NOW() - INTERVAL '24 hours'
ORDER BY d.timestamp DESC;
