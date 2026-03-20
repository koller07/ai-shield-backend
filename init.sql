-- ============================================
-- AI-SHIELD DATABASE SCHEMA
-- Atualizado com autenticação
-- ============================================

-- Tabela de empresas
CREATE TABLE IF NOT EXISTS companies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  admin_email VARCHAR(255) NOT NULL UNIQUE,
  plan VARCHAR(50) NOT NULL DEFAULT 'starter',
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  active BOOLEAN DEFAULT true,
  trial_ends_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Tabela de usuários (com autenticação)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
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
CREATE TABLE IF NOT EXISTS detections (
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
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
CREATE INDEX IF NOT EXISTS idx_detections_company ON detections(company_id);
CREATE INDEX IF NOT EXISTS idx_detections_user ON detections(user_id);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_companies_email ON companies(admin_email);

-- Trigger para atualizar updated_at automaticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_companies_updated_at BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

### **PASSO 3: Salvar**
1. Scroll para baixo
2. Em "Commit message" escrever: `Update database schema with authentication`
3. Clicar **"Commit changes"**

---

### **PASSO 4: Railway vai Re-deploy Automático**

O Railway detecta a mudança no GitHub e faz redeploy automático.

**AGUARDE 2-3 MINUTOS**

---

### **PASSO 5: Verificar Logs do Railway**

1. Voltar para Railway
2. Abrir "Deployments" 
3. Ver o novo deploy
4. Clicar em "View Logs"

**DEVE VER:**
```
✓ Database tables initialized
✓ Database connected
✓ AI-Shield Backend running on port 3000
✓ JWT Authentication: ENABLED
