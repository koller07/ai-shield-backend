-- ============================================
-- AI-SHIELD DATABASE SCHEMA
-- Versão simplificada sem triggers
-- ============================================

-- Limpar tabelas existentes (se houver)
DROP TABLE IF EXISTS detections CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS companies CASCADE;

-- Tabela de empresas
CREATE TABLE companies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  admin_email VARCHAR(255) NOT NULL UNIQUE,
  plan VARCHAR(50) NOT NULL DEFAULT 'starter',
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  active BOOLEAN DEFAULT true,
  trial_ends_at TIMESTAMP DEFAULT (NOW() + INTERVAL '14 days'),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Tabela de usuários
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255),
  role VARCHAR(50) DEFAULT 'user',
  active BOOLEAN DEFAULT true,
  last_login TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Tabela de detecções
CREATE TABLE detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  detection_type VARCHAR(50) NOT NULL,
  ai_platform VARCHAR(100),
  url TEXT,
  timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Índices para performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_company ON users(company_id);
CREATE INDEX idx_detections_company ON detections(company_id);
CREATE INDEX idx_detections_user ON detections(user_id);
CREATE INDEX idx_detections_timestamp ON detections(timestamp);
CREATE INDEX idx_companies_email ON companies(admin_email);
```
