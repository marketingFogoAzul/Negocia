-- Limpa tabelas antigas se existirem (CUIDADO: APAGA TUDO)
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS chats;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS dev_flag;
DROP TABLE IF EXISTS users;

-- 1. Tabela de Usuários (SEM profile_pic)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role INT NOT NULL DEFAULT 0, -- 0:Consumidor, 1:Vendedor, 2:Teste, 3:MKT/TI, 4:Junior, 5:Dev
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabela de Produtos
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    colors TEXT[] -- Array de strings para as cores
);

-- 3. Tabela de Chats (Negociações)
CREATE TABLE chats (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE SET NULL, -- Se o user for apagado, o chat fica (mas sem dono)
    status VARCHAR(50) DEFAULT 'active', -- active, pending_review, assumed, completed, manual_override (NOVO)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_to INT REFERENCES users(id) DEFAULT NULL, -- ID do Vendedor/Admin que assumiu
    proposal_data JSONB DEFAULT NULL, -- Guarda os dados finais (valor, qtd, etc.)
    review_requested BOOLEAN DEFAULT FALSE -- (NOVO) Garante que a revisão só pode ser pedida uma vez
);

-- 4. Tabela de Mensagens
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    chat_id INT REFERENCES chats(id) ON DELETE CASCADE, -- Se o chat for apagado, as msgs vão junto
    sender_type VARCHAR(50) NOT NULL, -- 'bot', 'user', ou 'admin' ou 'system'
    sender_id INT REFERENCES users(id) DEFAULT NULL, -- ID do user/admin (NULL se for 'bot' ou 'system')
    text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT REFERENCES users(id) ON DELETE SET NULL, -- Quem fez a ação
    user_email VARCHAR(100), -- Salva o email para o caso do usuário ser deletado
    action VARCHAR(255) NOT NULL, -- Ex: 'LOGIN', 'PROMOTION', 'CHAT_START'
    details TEXT, -- Ex: "Promoveu usuário 5 para cargo 3"
    target_user_id INT REFERENCES users(id) ON DELETE SET NULL -- (Opcional) Quem sofreu a ação
);

-- Inserindo alguns produtos mock para começar
INSERT INTO products (code, name, price, stock, colors) VALUES
('ZB-001', 'Cadeira Gamer Pro', 1800.00, 50, ARRAY['Preto', 'Vermelho', 'Azul']),
('ZB-002', 'Mesa de Escritório', 950.50, 30, ARRAY['Branco', 'Preto', 'Madeira']),
('ZB-003', 'Monitor Ultrawide 34"', 3200.00, 15, ARRAY['Preto'])
ON CONFLICT (code) DO NOTHING; -- Não insere se os códigos já existirem

-- Inserindo um usuário Vendedor para teste ( !! Gere seu próprio hash !! )
-- Exemplo para senha '123' (use: python -c "from flask_bcrypt import Bcrypt; print(Bcrypt().generate_password_hash('123').decode('utf-8'))")
INSERT INTO users (name, email, password_hash, role) VALUES
('Vendedor Teste', 'vendedor@zipbum.com', '$2b$12$EXAMPLEHASH.GENERATE.YOUR.OWN', 1)
ON CONFLICT (email) DO NOTHING;