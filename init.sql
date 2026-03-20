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

**SE NÃO ESTIVER IGUAL:**
- Clicar **Edit** (lápis)
- **Deletar tudo**
- **Colar** o SQL acima
- Commit: `Fix SQL syntax`

---

### **PASSO 2: Forçar Redeploy Railway**

Depois de atualizar o init.sql:

1. **Railway** → Seu projeto `ai-shield-backend`
2. Clicar nos **3 pontinhos (...)** no canto superior direito
3. Clicar **"Redeploy"**
4. Confirmar

**OU:**

1. GitHub → `ai-shield-backend` → qualquer arquivo (ex: README.md)
2. Edit → Adicionar um espaço
3. Commit: `Trigger redeploy`

---

### **PASSO 3: Verificar Logs Novos**

Aguardar 2-3 minutos e verificar logs:

**DEVE APARECER:**
```
✅ Database tables initialized
✅ Database connected
✅ AI-Shield Backend running on port 3000
✅ JWT Authentication: ENABLED
