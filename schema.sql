-- Limpa tabelas antigas se existirem (CUIDADO: APAGA TUDO)
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS chats;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS dev_flag;
DROP TABLE IF EXISTS users;

-- 1. Tabela de Usuários
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role INT NOT NULL DEFAULT 0, -- 0:Consumidor, 1:Vendedor, 2:Teste, 3:MKT/TI, 4:Junior, 5:Dev
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP -- Alterado
);

-- 2. Tabela de Produtos
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    colors TEXT[]
);

-- 3. Tabela de Chats (Negociações)
CREATE TABLE chats (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) DEFAULT 'active', -- active, pending_review, assumed, completed, manual_override
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Alterado
    assigned_to INT REFERENCES users(id) DEFAULT NULL,
    proposal_data JSONB DEFAULT NULL,
    review_requested BOOLEAN DEFAULT FALSE
);

-- 4. Tabela de Mensagens
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    chat_id INT REFERENCES chats(id) ON DELETE CASCADE,
    sender_type VARCHAR(50) NOT NULL, -- 'bot', 'user', 'admin', 'system'
    sender_id INT REFERENCES users(id) DEFAULT NULL,
    text TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP -- Alterado
);

-- 5. Flag para o comando secreto do Dev (Cargo 5)
CREATE TABLE dev_flag (
    id INT PRIMARY KEY DEFAULT 1,
    is_activated BOOLEAN DEFAULT FALSE,
    activated_by_user_id INT REFERENCES users(id) DEFAULT NULL
);
INSERT INTO dev_flag (id, is_activated) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING;

-- 6. Tabela de Logs de Auditoria
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Alterado
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(100),
    action VARCHAR(255) NOT NULL,
    details TEXT,
    target_user_id INT REFERENCES users(id) ON DELETE SET NULL
);

-- 7. Tabela de Filtros da IA (NOVA)
CREATE TABLE ia_filters (
    id SERIAL PRIMARY KEY,
    rule_type VARCHAR(50) NOT NULL, -- 'palavra_bloqueada', 'regra_prompt'
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id INT REFERENCES users(id)
);

-- Dados Iniciais (Exemplos)
INSERT INTO products (code, name, price, stock, colors) VALUES
('ZB-001', 'Cadeira Gamer Pro', 1800.00, 50, ARRAY['Preto', 'Vermelho', 'Azul']),
('ZB-002', 'Mesa de Escritório', 950.50, 30, ARRAY['Branco', 'Preto', 'Madeira']),
('ZB-003', 'Monitor Ultrawide 34"', 3200.00, 15, ARRAY['Preto'])
ON CONFLICT (code) DO NOTHING;

-- Senha '123' para os usuários de teste (gere seus próprios hashes em produção!)
-- $2b$12$EXAMPLEHASH.GENERATE.YOUR.OWN (exemplo, use o seu hash real)
-- Use este hash gerado para a senha '123': $2b$12$DWOv4T3K.QylfQ4QxVrQGeC8S1XpYm.x6uJhqPsE3A.k6Z/i4gYuy
INSERT INTO users (name, email, password_hash, role) VALUES
('Vendedor Teste', 'vendedor@zipbum.com', '$2b$12$DWOv4T3K.QylfQ4QxVrQGeC8S1XpYm.x6uJhqPsE3A.k6Z/i4gYuy', 1),
('Admin Teste', 'admin@zipbum.com', '$2b$12$DWOv4T3K.QylfQ4QxVrQGeC8S1XpYm.x6uJhqPsE3A.k6Z/i4gYuy', 3),
('Consumidor Teste', 'cliente@email.com', '$2b$12$DWOv4T3K.QylfQ4QxVrQGeC8S1XpYm.x6uJhqPsE3A.k6Z/i4gYuy', 0)
ON CONFLICT (email) DO NOTHING;