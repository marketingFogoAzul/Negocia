import os
import psycopg2
import json
import re
import google.generativeai as genai
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, jsonify, session, redirect, url_for, flash, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime

# --- INICIALIZAÇÃO E CONFIGS ---
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# Configuração do Gemini
try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-pro')
    GEMINI_AVAILABLE = True
    print("✅ Gemini AI configurado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao configurar Gemini: {e}")
    GEMINI_AVAILABLE = False
    gemini_model = None

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "danger"

# --- MODELO DE USUÁRIO ---
class User(UserMixin):
    def __init__(self, id, name, email, role):
        self.id = id
        self.name = name
        self.email = email
        self.role = role

    def has_role(self, *role_numbers):
        return self.role in role_numbers

    def can(self, permission):
        """Sistema de permissão granular"""
        if self.role == 5: 
            return True
        if self.role == 4:
            if permission == 'promote_to_admin': 
                return False
            return True
        if self.role == 3:
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product', 
                'access_review', 'view_admin_panel', 'promote_to_junior', 'view_logs',
                'view_all_negotiations', 'close_chat'
            ]
        if self.role == 2:
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product',
                'access_review', 'view_admin_panel', 'view_logs',
                'view_all_negotiations', 'close_chat'
            ]
        if self.role == 1:
            return permission in ['view_chat', 'assume_negotiation', 'access_review', 'close_chat']
        if self.role == 0:
            return permission in ['view_chat', 'close_chat']
        return False

@login_manager.user_loader
def load_user(user_id):
    """Carrega o usuário da sessão"""
    conn = get_db_connection()
    if not conn: 
        return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, name, email, role FROM users WHERE id = %s", (int(user_id),))
            user_data = cur.fetchone()
            if user_data:
                return User(
                    user_data['id'], 
                    user_data['name'], 
                    user_data['email'], 
                    user_data['role']
                )
        return None
    except Exception as e:
        print(f"Erro ao carregar usuário: {e}")
        return None
    finally:
        if conn: 
            conn.close()

# --- DECORADORES E FUNÇÕES DE DB ---
def role_required(min_role=0):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: 
                return login_manager.unauthorized()
            if current_user.role < min_role:
                flash("Você não tem permissão para acessar esta página.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: 
                return login_manager.unauthorized()
            if not current_user.can(permission): 
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Erro crítico ao conectar no Neon DB: {e}")
        return None

def query_db(query, args=(), one=False):
    conn = get_db_connection()
    if not conn: 
        return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, args)
            result = cur.fetchone() if one else cur.fetchall()
            return result
    except Exception as e:
        print(f"Erro ao executar query: {e}")
        return None
    finally:
        if conn: 
            conn.close()

def execute_db(query, args=(), returning_id=False):
    conn = get_db_connection()
    if not conn: 
        return False
    try:
        with conn.cursor() as cur:
            cur.execute(query, args)
            conn.commit()
            if returning_id:
                return cur.fetchone()[0]
            return True
    except Exception as e:
        print(f"Erro ao executar comando: {e}")
        conn.rollback()
        return False
    finally:
        if conn: 
            conn.close()

# --- FUNÇÕES DE LOG E DEV FLAG ---
def log_action(user, action, details=None, target_user_id=None):
    try:
        user_id = user.id if user else None
        user_email = user.email if user else 'System'
        execute_db(
            "INSERT INTO audit_log (user_id, user_email, action, details, target_user_id) VALUES (%s, %s, %s, %s, %s)",
            (user_id, user_email, action, details, target_user_id)
        )
    except Exception as e:
        print(f"Erro CRÍTICO ao salvar log de auditoria: {e}")

def check_dev_flag():
    result = query_db("SELECT is_activated FROM dev_flag WHERE id = 1", one=True)
    return result['is_activated'] if result else False

def activate_dev_flag(user):
    conn = get_db_connection()
    if not conn: 
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE dev_flag SET is_activated = TRUE, activated_by_user_id = %s WHERE id = 1 AND is_activated = FALSE", (user.id,))
            if cur.rowcount == 0:
                conn.rollback()
                return False
            cur.execute("UPDATE users SET role = 5 WHERE id = %s", (user.id,))
            conn.commit()
            log_action(user, 'DEV_MODE_ACTIVATED', details="Comando secreto Qazxcvbnmlp7@ utilizado.")
            return True
    except Exception as e:
        print(f"Erro ao ativar flag Dev: {e}")
        conn.rollback()
        return False
    finally:
        if conn: 
            conn.close()

# --- FUNÇÃO GEMINI AI ---
def get_gemini_response(user_message, chat_history=None, product_info=None):
    """Obtém resposta do Gemini AI baseada no contexto da conversa"""
    if not GEMINI_AVAILABLE:
        return "Desculpe, o serviço de IA não está disponível no momento."
    
    try:
        # Construir contexto da conversa
        context = """
        Você é um assistente de vendas da empresa ZIPBUM Negocia, especializado em ajudar clientes 
        com negociações de produtos. Seja educado, profissional e sempre mantenha o foco no atendimento.
        
        Suas respostas devem ser em português brasileiro e sempre focadas em ajudar o cliente a 
        encontrar o produto certo e finalizar a negociação.
        """
        
        if product_info:
            context += f"\n\nInformações do produto em discussão: {product_info}"
        
        if chat_history:
            context += "\n\nHistórico recente da conversa:"
            for msg in chat_history[-6:]:  # Últimas 6 mensagens para contexto
                role = "Usuário" if msg['sender_type'] == 'user' else "Assistente"
                context += f"\n{role}: {msg['text']}"
        
        prompt = f"{context}\n\nUsuário: {user_message}\nAssistente:"
        
        response = gemini_model.generate_content(prompt)
        return response.text.strip()
        
    except Exception as e:
        print(f"Erro ao chamar Gemini AI: {e}")
        return "Desculpe, ocorreu um erro ao processar sua mensagem. Por favor, tente novamente."

# --- ROTAS DE PÁGINAS (VIEW/CONTROLLER) ---
# ... (todo o seu código anterior mantido)

# --- ROTAS CORRETAS ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: 
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Processar login via form tradicional
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        user_data = query_db("SELECT id, name, email, password_hash, role FROM users WHERE email = %s", (email,), one=True)
        
        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['name'], user_data['email'], user_data['role'])
            login_user(user, remember=remember)
            session.pop('chat_state', None)
            log_action(user, 'LOGIN')
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('E-mail ou senha inválidos!', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: 
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Processar registro via form tradicional
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not name or not email or not password:
            flash('Preencha todos os campos!', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
            return render_template('register.html')
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Formato de e-mail inválido!', 'danger')
            return render_template('register.html')
        
        if query_db("SELECT id FROM users WHERE email = %s", (email,), one=True):
            flash('Este e-mail já está em uso!', 'danger')
            return render_template('register.html')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user_id = execute_db(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 0) RETURNING id",
            (name, email, hashed_password),
            returning_id=True
        )
        
        if user_id:
            user = User(id=user_id, name=name, email=email, role=0)
            login_user(user)
            log_action(user, 'REGISTER', details=f"Nova conta criada: {email}")
            flash('Conta criada com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Erro ao criar conta!', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user, 'LOGOUT')
    logout_user()
    session.clear()
    flash("Você saiu com sucesso.", "success")
    return redirect(url_for('login'))

@app.route('/')
@app.route('/home')
@login_required
def home():
    # Buscar chats recentes
    recent_chats = query_db("""
        SELECT c.id, c.contact_name, c.status, c.created_at, c.last_activity, 
               c.last_message, c.unread_count,
               COALESCE(p.name, 'Nova Negociação') as product_name
        FROM chats c 
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s 
        ORDER BY c.last_activity DESC 
        LIMIT 10
    """, (current_user.id,)) or []
    
    # Estatísticas
    total_chats = query_db("SELECT COUNT(id) as c FROM chats WHERE user_id = %s", (current_user.id,), one=True) or {'c': 0}
    active_chats = query_db("SELECT COUNT(id) as c FROM chats WHERE user_id = %s AND status = 'active'", (current_user.id,), one=True) or {'c': 0}
    
    return render_template('home.html', 
                         recent_chats=recent_chats,
                         total_chats=total_chats['c'],
                         active_chats=active_chats['c'])

# ... (restante das suas rotas mantidas)
    # Busca chats recentes do usuário para a sidebar - CORRIGIDO
    recent_chats = query_db("""
        SELECT c.id, c.contact_name, c.status, c.created_at, c.last_activity, 
               c.last_message, c.unread_count, c.assigned_to,
               COALESCE(p.name, 'Nova Negociação') as product_name
        FROM chats c 
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s 
        ORDER BY c.last_activity DESC 
        LIMIT 10
    """, (current_user.id,))
    
    return render_template('home.html', recent_chats=recent_chats or [])

@app.route('/new_chat')  # CORRIGIDO: era '/chat'
@login_required
def new_chat_page():
    session.pop('chat_state', None)
    session.pop('current_chat_id', None)
    session.pop('negotiation_data', None)
    
    # Busca chats recentes para sidebar - CORRIGIDO
    recent_chats = query_db("""
        SELECT c.id, c.contact_name, c.status, c.created_at, c.last_activity,
               c.last_message, c.unread_count,
               COALESCE(p.name, 'Nova Negociação') as product_name
        FROM chats c 
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s 
        ORDER BY c.last_activity DESC 
        LIMIT 10
    """, (current_user.id,))
    
    return render_template('new_chat.html', recent_chats=recent_chats or [])  # CORRIGIDO: template correto

@app.route('/chat/<int:chat_id>')
@login_required
def chat(chat_id):  # CORRIGIDO: nome da função
    # Puxa dados do chat E do usuário que o criou - CORRIGIDO
    chat = query_db("""
        SELECT c.*, u.name as user_name, u.email as user_email 
        FROM chats c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.id = %s
    """, (chat_id,), one=True)
    
    if not chat: 
        abort(404)
    
    # Verifica permissão
    if chat['user_id'] != current_user.id and current_user.role < 1:
        abort(403)
    
    # Carrega histórico, juntando nome do admin (se houver) - CORRIGIDO
    history = query_db("""
        SELECT m.sender_type, m.text, m.timestamp, u.name as sender_name, m.is_from_user
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id AND m.sender_type = 'admin'
        WHERE m.chat_id = %s 
        ORDER BY m.timestamp ASC
    """, (chat_id,))
    
    # Busca chats recentes para sidebar - CORRIGIDO
    recent_chats = query_db("""
        SELECT c.id, c.contact_name, c.status, c.created_at, c.last_activity,
               c.last_message, c.unread_count,
               COALESCE(p.name, 'Nova Negociação') as product_name
        FROM chats c 
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s 
        ORDER BY c.last_activity DESC 
        LIMIT 10
    """, (current_user.id,))
    
    session.pop('chat_state', None)
    return render_template('chat.html', 
                         chat_data=chat, 
                         chat_history=history or [], 
                         chat_id=chat_id,
                         recent_chats=recent_chats or [])

@app.route('/contacts')  # CORRIGIDO: rota adicionada
@login_required
def contacts():
    chats = query_db("""
        SELECT c.id, c.contact_name, c.contact_phone, c.status, c.created_at, c.last_activity
        FROM chats c 
        WHERE c.user_id = %s 
        ORDER BY c.contact_name ASC
    """, (current_user.id,))
    
    return render_template('contacts.html', contacts=chats or [])

@app.route('/reports')  # CORRIGIDO: rota adicionada
@login_required
def reports():
    total_chats = query_db("SELECT COUNT(id) as c FROM chats WHERE user_id = %s", (current_user.id,), one=True)['c'] or 0
    total_messages = query_db("""
        SELECT COUNT(m.id) as c 
        FROM messages m 
        JOIN chats c ON m.chat_id = c.id 
        WHERE c.user_id = %s
    """, (current_user.id,), one=True)['c'] or 0
    active_chats = query_db("SELECT COUNT(id) as c FROM chats WHERE user_id = %s AND status = 'active'", (current_user.id,), one=True)['c'] or 0
    
    return render_template('reports.html', 
                         total_chats=total_chats, 
                         total_messages=total_messages,
                         active_chats=active_chats)

# --- PAINEL ADMINISTRATIVO (ROTAS /admin/...) ---
@app.route('/admin')
@login_required
@role_required(min_role=2)
def admin_panel():
    stats = {
        'total_users': query_db("SELECT COUNT(id) as c FROM users", one=True)['c'] or 0,
        'total_products': query_db("SELECT COUNT(id) as c FROM products", one=True)['c'] or 0,
        'pending_reviews': query_db("SELECT COUNT(id) as c FROM chats WHERE status = 'pending_review'", one=True)['c'] or 0,
        'total_negotiations': query_db("SELECT COUNT(id) as c FROM chats", one=True)['c'] or 0
    }
    
    reviews = query_db("""
        SELECT c.id, u.name as user_name, c.created_at, p.name as product_name, c.contact_name
        FROM chats c 
        JOIN users u ON c.user_id = u.id 
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.status = 'pending_review' 
        ORDER BY c.created_at DESC 
        LIMIT 5
    """) or []
    
    # Status do Gemini
    gemini_status = "online" if GEMINI_AVAILABLE else "offline"
    
    return render_template('admin/admin_panel.html', 
                         stats=stats, 
                         reviews=reviews,
                         gemini_status=gemini_status)

@app.route('/admin/products')
@login_required
@permission_required('insert_product')
def admin_products():
    products = query_db("SELECT * FROM products ORDER BY name ASC") or []
    return render_template('admin/admin_products.html', products=products)

@app.route('/admin/users')
@login_required
@permission_required('promote_to_junior')
def admin_users():
    dev_activated = check_dev_flag()
    query = "SELECT id, name, email, role, created_at FROM users WHERE role < %s"
    args = [current_user.role]
    
    if dev_activated:
        query += " AND role != 5"
    
    query += " ORDER BY name ASC"
    users = query_db(query, tuple(args)) or []
    
    return render_template('admin/admin_users.html', users=users, dev_activated=dev_activated)

@app.route('/admin/negotiations')
@login_required
@permission_required('access_review')
def admin_negotiations():
    search_query = request.args.get('q', '').strip()
    filter_vendedor_id = request.args.get('vendedor', '')
    
    base_query = """
        SELECT c.id, c.status, c.created_at, c.contact_name, c.contact_phone,
               u.name as user_name, u.email as user_email, 
               a.name as assigned_admin,
               p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN users a ON c.assigned_to = a.id
        LEFT JOIN products p ON c.product_id = p.id
    """
    
    args = []
    conditions = []

    if current_user.role == 1:
        # Vendedor (Cargo 1) SÓ PODE ver os chats atribuídos a ele
        conditions.append("c.assigned_to = %s")
        args.append(current_user.id)
    elif current_user.role == 0:
        # Consumidor (Cargo 0) só pode ver os seus
        conditions.append("c.user_id = %s")
        args.append(current_user.id)
    elif current_user.can('view_all_negotiations'):
        # Admin (Cargo 2+) pode filtrar por vendedor
        if filter_vendedor_id:
            conditions.append("c.assigned_to = %s")
            args.append(int(filter_vendedor_id))
    
    if search_query:
        search_term_like = f"%{search_query}%"
        search_condition = "(u.name ILIKE %s OR u.email ILIKE %s OR c.contact_name ILIKE %s)"
        args.extend([search_term_like, search_term_like, search_term_like])
        
        try:
            chat_id_int = int(search_query)
            search_condition += " OR c.id = %s"
            args.append(chat_id_int)
        except ValueError:
            pass
        
        conditions.append(search_condition)

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY c.created_at DESC"
    
    negotiations = query_db(base_query, tuple(args)) or []
    
    vendedores = []
    if current_user.can('view_all_negotiations'):
        vendedores = query_db("SELECT id, name FROM users WHERE role >= 1 ORDER BY name ASC") or []
    
    return render_template('admin/admin_negotiations.html', 
                           negotiations=negotiations, 
                           vendedores=vendedores,
                           search_query=search_query,
                           filter_vendedor_id=int(filter_vendedor_id) if filter_vendedor_id else None)

@app.route('/admin/logs')
@login_required
@permission_required('view_logs')
def admin_logs():
    page = request.args.get('page', 1, type=int)
    limit = 50
    offset = (page - 1) * limit
    
    logs = query_db(
        "SELECT timestamp, user_email, action, details, target_user_id FROM audit_log ORDER BY timestamp DESC LIMIT %s OFFSET %s",
        (limit, offset)
    ) or []
    
    total_logs_result = query_db("SELECT COUNT(id) as c FROM audit_log", one=True)
    total_logs = total_logs_result['c'] if total_logs_result else 0
    total_pages = (total_logs // limit) + (1 if total_logs % limit > 0 else 0)
    
    return render_template('admin/admin_logs.html', 
                           logs=logs, 
                           current_page=page, 
                           total_pages=total_pages)

# --- API DE AUTENTICAÇÃO ---
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not name or not email or not password or len(password) < 6:
        return jsonify({'success': False, 'message': 'Preencha todos os campos (senha mín. 6 caracteres).'}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'success': False, 'message': 'Formato de e-mail inválido.'}), 400
    
    if query_db("SELECT id FROM users WHERE email = %s", (email,), one=True):
        return jsonify({'success': False, 'message': 'Este e-mail já está em uso.'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    user_id = execute_db(
        "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 0) RETURNING id",
        (name, email, hashed_password),
        returning_id=True
    )
    
    if not user_id:
        return jsonify({'success': False, 'message': 'Erro no servidor ao criar usuário.'}), 500

    user = User(id=user_id, name=name, email=email, role=0)
    login_user(user)
    log_action(user, 'REGISTER', details=f"Nova conta criada: {email}")
    
    return jsonify({'success': True, 'message': 'Registro bem-sucedido!'})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'E-mail e senha são obrigatórios.'}), 400

    user_data = query_db("SELECT id, name, email, password_hash, role FROM users WHERE email = %s", (email,), one=True)
    
    if not user_data:
        log_action(None, 'LOGIN_FAILED', details=f"Tentativa falha (email não encontrado): {email}")
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    if bcrypt.check_password_hash(user_data['password_hash'], password):
        user = User(
            id=user_data['id'],
            name=user_data['name'],
            email=user_data['email'],
            role=user_data['role']
        )
        login_user(user)
        session.pop('chat_state', None)
        log_action(user, 'LOGIN')
        return jsonify({'success': True, 'message': 'Login bem-sucedido!'})
    else:
        log_action(None, 'LOGIN_FAILED', details=f"Tentativa falha (senha incorreta): {email}")
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

# --- API DO CHAT (LÓGICA PRINCIPAL) ---
def save_message(chat_id, sender_type, text, sender_id=None):
    """Função helper para salvar qualquer mensagem no DB."""
    return execute_db(
        "INSERT INTO messages (chat_id, sender_type, sender_id, text, is_from_user) VALUES (%s, %s, %s, %s, %s)",
        (chat_id, sender_type, sender_id, text, sender_type == 'user')
    )

def process_chat_state_machine(user_message, user):
    """Processa a mensagem do usuário (IA - Máquina de Estado)."""
    state = session.get('chat_state', 'START')
    chat_id = session.get('current_chat_id')
    negotiation = session.get('negotiation_data', {})
    bot_response = "Desculpe, não entendi."
    show_review_button = False

    if not chat_id:
        new_chat_id = execute_db(
            "INSERT INTO chats (user_id, status, contact_name, contact_phone) VALUES (%s, 'active', %s, %s) RETURNING id", 
            (user.id, 'Novo Contato', ''), 
            returning_id=True
        )
        if not new_chat_id:
            return {'sender_type': 'bot', 'text': 'Erro: Não consegui iniciar um novo chat.', 'lock': True}
        
        chat_id = new_chat_id
        session['current_chat_id'] = chat_id
        log_action(user, 'CHAT_START', details=f"Iniciou chat ID: {chat_id}")
        save_message(chat_id, 'user', user_message, user.id)
    else:
        save_message(chat_id, 'user', user_message, user.id)
        # Atualiza o timestamp do chat
        execute_db("UPDATE chats SET last_activity = CURRENT_TIMESTAMP WHERE id = %s", (chat_id,))

    # --- LÓGICA DA MÁQUINA DE ESTADO ---
    if state == 'START':
        product = query_db(
            "SELECT * FROM products WHERE (name ILIKE %s OR code ILIKE %s) AND stock > 0", 
            (f"%{user_message}%", f"%{user_message}%"), 
            one=True
        )
        
        if product:
            bot_response = f"Produto encontrado: {product['name']}. (Estoque: {product['stock']}). Quantas unidades você deseja?"
            negotiation = {
                'product_id': product['id'], 
                'product_name': product['name'],
                'product_price': float(product['price']), 
                'max_stock': product['stock']
            }
            state = 'AWAITING_QUANTITY'
        else:
            # Usa Gemini para responder quando não encontra produto
            chat_history = query_db(
                "SELECT sender_type, text FROM messages WHERE chat_id = %s ORDER BY timestamp ASC",
                (chat_id,)
            )
            bot_response = get_gemini_response(user_message, chat_history)
            state = 'START'

    elif state == 'AWAITING_QUANTITY':
        try:
            quantity = int(user_message)
            if 0 < quantity <= negotiation.get('max_stock', 0):
                negotiation['quantity'] = quantity
                product_colors = query_db(
                    "SELECT colors FROM products WHERE id = %s", 
                    (negotiation['product_id'],), 
                    one=True
                )
                
                if product_colors and product_colors['colors'] and len(product_colors['colors']) > 0:
                    negotiation['available_colors'] = product_colors['colors']
                    bot_response = f"Entendido, {quantity} unidades. Qual cor você prefere? ({', '.join(product_colors['colors'])})"
                    state = 'AWAITING_COLOR'
                else:
                    negotiation['color'] = 'N/A'
                    bot_response = "Ótimo. Agora, qual o tipo de entrega? (Ex: Padrão, Expressa)"
                    state = 'AWAITING_DELIVERY'
            else:
                bot_response = f"Quantidade inválida. Temos {negotiation.get('max_stock', 0)} em estoque."
                state = 'AWAITING_QUANTITY'
                
        except (ValueError, KeyError):
            bot_response = "Ocorreu um erro, vamos recomeçar. Qual produto você deseja?"
            state = 'START'
            negotiation = {}

    elif state == 'AWAITING_COLOR':
        try:
            chosen_color = user_message.strip().capitalize()
            if 'available_colors' in negotiation and chosen_color in negotiation['available_colors']:
                negotiation['color'] = chosen_color
                bot_response = "Cor selecionada. Agora, qual o tipo de entrega? (Ex: Padrão, Expressa)"
                state = 'AWAITING_DELIVERY'
            else:
                colors_str = ", ".join(negotiation.get('available_colors', []))
                bot_response = f"Cor inválida. Por favor, escolha uma das opções: ({colors_str})"
                state = 'AWAITING_COLOR'
                
        except KeyError:
            bot_response = "Ocorreu um erro, vamos recomeçar. Qual produto você deseja?"
            state = 'START'
            negotiation = {}

    elif state == 'AWAITING_DELIVERY':
        try:
            negotiation['delivery'] = user_message
            total_value = negotiation['product_price'] * negotiation['quantity']
            negotiation['total_value'] = total_value
            
            bot_response = (
                f"Certo! Sua proposta é:\n"
                f"Produto: {negotiation['product_name']} (Qtd: {negotiation['quantity']}, Cor: {negotiation['color']})\n"
                f"Entrega: {negotiation['delivery']}\n"
                f"Valor Total: R$ {total_value:.2f}\n\n"
                "Se estiver tudo certo, clique em 'Solicitar Revisão' abaixo para um de nossos vendedores analisar."
            )
            
            show_review_button = True
            state = 'AWAITING_REVIEW'
            proposal_json = json.dumps(negotiation)
            
            # Atualiza product_id e proposal_data
            execute_db(
                "UPDATE chats SET proposal_data = %s, product_id = %s, last_activity = CURRENT_TIMESTAMP, last_message = %s WHERE id = %s", 
                (proposal_json, negotiation['product_id'], bot_response[:100], chat_id)
            )
            
        except KeyError:
            bot_response = "Ocorreu um erro, vamos recomeçar. Qual produto você deseja?"
            state = 'START'
            negotiation = {}
            
    elif state == 'AWAITING_REVIEW':
        bot_response = "Por favor, clique em 'Solicitar Revisão' para continuar ou reinicie a negociação."
        show_review_button = True

    session['chat_state'] = state
    session['negotiation_data'] = negotiation
    save_message(chat_id, 'bot', bot_response, None)
    
    # Atualiza timestamp do chat
    execute_db("UPDATE chats SET last_activity = CURRENT_TIMESTAMP, last_message = %s WHERE id = %s", (bot_response[:100], chat_id))
    
    return {
        'sender_type': 'bot', 
        'text': bot_response, 
        'chat_id': chat_id, 
        'show_review_button': show_review_button,
        'chat_status': 'active'
    }

@app.route('/api/chat/user_message', methods=['POST'])
@login_required
def api_chat_user_message():
    data = request.json
    user_message = data.get('message', '').strip()
    
    if not user_message: 
        return jsonify({'error': 'Mensagem vazia'}), 400
    
    user = current_user
    chat_id = session.get('current_chat_id')
    
    if chat_id:
        chat = query_db("SELECT status FROM chats WHERE id = %s", (chat_id,), one=True)
        if chat and chat['status'] != 'active':
            save_message(chat_id, 'user', user_message, user.id)
            bot_response = "Este chat está sendo analisado por um vendedor. Por favor, aguarde a resposta."
            if chat['status'] == 'completed':
                bot_response = "Esta negociação foi encerrada."
            save_message(chat_id, 'bot', bot_response, None)
            return jsonify({
                'sender_type': 'bot', 
                'text': bot_response, 
                'chat_status': chat['status']
            })
    
    # Comando secreto para modo desenvolvedor
    if user_message == "Qazxcvbnmlp7@":
        if check_dev_flag(): 
            response_text = "Comando já utilizado."
        else:
            success = activate_dev_flag(user)
            response_text = "MODO DESENVOLVEDOR ATIVADO." if success else "Comando já utilizado por outro."
        
        if chat_id:
            save_message(chat_id, 'user', '*** COMANDO SECRETO ***', user.id)
            save_message(chat_id, 'bot', response_text, None)
        
        return jsonify({'sender_type': 'bot', 'text': response_text})

    response = process_chat_state_machine(user_message, user)
    return jsonify(response)

@app.route('/api/chat/request_review/<int:chat_id>', methods=['POST'])
@login_required
def api_request_review(chat_id):
    chat = query_db("SELECT id, user_id, status, review_requested FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat or chat['user_id'] != current_user.id:
        return jsonify({'success': False, 'message': 'Chat não encontrado ou não autorizado.'}), 404
    
    if chat['status'] != 'active':
        return jsonify({'success': False, 'message': 'Este chat já foi enviado para revisão.'}), 400
    
    if chat['review_requested']:
        return jsonify({'success': False, 'message': 'Revisão já foi solicitada para este chat.'}), 400
        
    success = execute_db(
        "UPDATE chats SET status = 'pending_review', review_requested = TRUE, last_activity = CURRENT_TIMESTAMP WHERE id = %s", 
        (chat_id,)
    )
    
    if success:
        log_action(current_user, 'REQUEST_REVIEW', details=f"Usuário solicitou revisão para o chat ID: {chat_id}")
        bot_response = "Sua solicitação foi enviada! Um de nossos vendedores assumirá esta conversa em breve."
        save_message(chat_id, 'bot', bot_response, None)
        
        return jsonify({
            'success': True, 
            'message': bot_response, 
            'sender_type': 'bot',
            'chat_status': 'pending_review'
        })
    else:
        return jsonify({'success': False, 'message': 'Erro ao solicitar revisão.'}), 500

@app.route('/api/chat/admin_message/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_chat_admin_message(chat_id):
    data = request.json
    admin_message = data.get('message', '').strip()
    
    if not admin_message: 
        return jsonify({'error': 'Mensagem vazia'}), 400
    
    admin_user = current_user
    chat = query_db("SELECT id, user_id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat: 
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    if admin_user.role == 1 and chat['assigned_to'] != admin_user.id:
        return jsonify({'success': False, 'message': 'Você não pode responder este chat.'}), 403
    
    if chat['status'] == 'completed':
        return jsonify({'success': False, 'message': 'Este chat já foi encerrado.'}), 400
        
    if chat['status'] == 'pending_review':
        execute_db(
            "UPDATE chats SET status = 'assumed', assigned_to = %s, last_activity = CURRENT_TIMESTAMP WHERE id = %s", 
            (admin_user.id, chat_id)
        )
        log_action(admin_user, 'ASSUME_CHAT', details=f"Assumiu (respondendo) chat ID: {chat_id}")
    
    save_message(chat_id, 'admin', admin_message, admin_user.id)
    
    # Atualiza last_message do chat
    execute_db("UPDATE chats SET last_message = %s, last_activity = CURRENT_TIMESTAMP WHERE id = %s", (admin_message[:100], chat_id))
    
    return jsonify({
        'success': True, 
        'sender_type': 'admin', 
        'text': admin_message, 
        'sender_name': admin_user.name
    })

@app.route('/api/chat/disable_ia/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_disable_ia(chat_id):
    chat = query_db("SELECT id, status FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat:
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    if chat['status'] == 'completed':
        return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400
    
    success = execute_db(
        "UPDATE chats SET status = 'manual_override', last_activity = CURRENT_TIMESTAMP WHERE id = %s", 
        (chat_id,)
    )
    
    if success:
        log_action(current_user, 'DISABLE_IA', details=f"Desativou IA do chat ID: {chat_id}")
        msg_text = f"{current_user.name} desativou a IA para este chat. Atendimento manual ativo."
        save_message(chat_id, 'system', msg_text, None)
        
        return jsonify({
            'success': True, 
            'message': msg_text, 
            'sender_type': 'system',
            'chat_status': 'manual_override'
        })
    else:
        return jsonify({'success': False, 'message': 'Erro ao desativar IA.'}), 500

@app.route('/api/chat/close/<int:chat_id>', methods=['POST'])
@login_required
@permission_required('close_chat')
def api_close_chat(chat_id):
    chat = query_db("SELECT id, user_id, assigned_to, status FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat: 
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    if chat['status'] == 'completed': 
        return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400
        
    is_owner = chat['user_id'] == current_user.id
    is_assigned = chat['assigned_to'] == current_user.id
    is_admin = current_user.role >= 2
    
    if not is_owner and not is_assigned and not is_admin:
        return jsonify({'success': False, 'message': 'Você não tem permissão para encerrar este chat.'}), 403

    success = execute_db(
        "UPDATE chats SET status = 'completed', last_activity = CURRENT_TIMESTAMP WHERE id = %s", 
        (chat_id,)
    )
    
    if success:
        log_action(current_user, 'CHAT_CLOSED', details=f"Chat ID: {chat_id} foi encerrado.")
        msg_text = f"Negociação encerrada por {current_user.name}."
        save_message(chat_id, 'system', msg_text, None)
        
        return jsonify({
            'success': True, 
            'message': msg_text, 
            'sender_type': 'system',
            'chat_status': 'completed'
        })
    else:
        return jsonify({'success': False, 'message': 'Erro ao encerrar o chat.'}), 500

@app.route('/api/admin/pending_reviews_count', methods=['GET'])
@login_required
@role_required(min_role=2)
def api_pending_reviews_count():
    result = query_db("SELECT COUNT(id) as c FROM chats WHERE status = 'pending_review'", one=True)
    count = result['c'] if result else 0
    return jsonify({'count': count})

# --- APIs DE ADMIN (PRODUTOS, USUÁRIOS, ASSUMIR) ---
@app.route('/api/admin/products', methods=['POST'])
@login_required
@permission_required('insert_product')
def api_add_product():
    data = request.json
    try:
        code = data['code']
        name = data['name']
        price = float(data['price'])
        stock = int(data['stock'])
        colors = [c.strip().capitalize() for c in data.get('colors', '').split(',') if c.strip()]
        
        if not code or not name or price <= 0 or stock < 0: 
            return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
        
        if query_db("SELECT id FROM products WHERE code = %s", (code,), one=True): 
            return jsonify({'success': False, 'message': 'Este código já existe.'}), 409
        
        success = execute_db(
            "INSERT INTO products (code, name, price, stock, colors) VALUES (%s, %s, %s, %s, %s)", 
            (code, name, price, stock, colors)
        )
        
        if success:
            log_action(current_user, 'PRODUCT_ADD', details=f"Produto: {name} ({code})")
            return jsonify({'success': True, 'message': 'Produto adicionado com sucesso!'})
        else: 
            return jsonify({'success': False, 'message': 'Erro ao salvar no banco de dados.'}), 500
            
    except Exception as e: 
        return jsonify({'success': False, 'message': f'Erro: {e}'}), 400

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@login_required
@permission_required('remove_product')
def api_delete_product(product_id):
    product = query_db("SELECT name, code FROM products WHERE id = %s", (product_id,), one=True)
    product_name = f"{product['name']} ({product['code']})" if product else f"ID {product_id}"
    
    success = execute_db("DELETE FROM products WHERE id = %s", (product_id,))
    
    if success:
        log_action(current_user, 'PRODUCT_REMOVE', details=f"Produto: {product_name}")
        return jsonify({'success': True, 'message': 'Produto removido.'})
    else: 
        return jsonify({'success': False, 'message': 'Erro ao remover. Produto pode estar em uso.'}), 500

@app.route('/api/admin/users/promote', methods=['POST'])
@login_required
@permission_required('promote_to_junior')
def api_promote_user():
    data = request.json
    try: 
        user_id_to_promote = int(data['userId'])
        new_role = int(data['newRole'])
    except Exception: 
        return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
    
    admin_role = current_user.role
    
    if user_id_to_promote == current_user.id: 
        return jsonify({'success': False, 'message': 'Você não pode alterar seu próprio cargo.'}), 403
    
    if new_role >= admin_role: 
        return jsonify({'success': False, 'message': 'Você não pode promover para um cargo igual ou superior ao seu.'}), 403
    
    if new_role == 5: 
        return jsonify({'success': False, 'message': 'O cargo 5 (Dev) não pode ser atribuído manualmente.'}), 403
    
    target_user = query_db("SELECT role, email FROM users WHERE id = %s", (user_id_to_promote,), one=True)
    
    if not target_user: 
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404
    
    if target_user['role'] >= admin_role and target_user['role'] != 5: 
        return jsonify({'success': False, 'message': 'Você não pode alterar o cargo de um admin de nível igual ou superior.'}), 403
    
    old_role = target_user['role']
    success = execute_db("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id_to_promote))
    
    if success:
        log_action(
            current_user, 
            'PROMOTION', 
            details=f"Alterou cargo de {old_role} para {new_role} (Email: {target_user['email']})",
            target_user_id=user_id_to_promote
        )
        return jsonify({'success': True, 'message': 'Cargo do usuário atualizado!'})
    else: 
        return jsonify({'success': False, 'message': 'Erro ao atualizar o banco de dados.'}), 500

@app.route('/api/admin/negotiations/assume/<int:chat_id>', methods=['POST'])
@login_required
@permission_required('assume_negotiation')
def api_assume_negotiation(chat_id):
    admin_user = current_user
    chat = query_db("SELECT status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat: 
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    if chat['status'] != 'pending_review':
        return jsonify({'success': False, 'message': 'Este chat não está pendente de revisão.'}), 409

    success = execute_db(
        "UPDATE chats SET status = 'assumed', assigned_to = %s, last_activity = CURRENT_TIMESTAMP WHERE id = %s", 
        (admin_user.id, chat_id)
    )
    
    if success:
        log_action(admin_user, 'ASSUME_CHAT', details=f"Assumiu (pelo botão) chat ID: {chat_id}")
        msg_text = f"{admin_user.name} assumiu esta negociação."
        save_message(chat_id, 'system', msg_text, None)
        return jsonify({'success': True, 'message': 'Você assumiu a negociação.'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao assumir o chat.'}), 500

# --- PONTO DE ENTRADA ---
if __name__ == '__main__':
    # Inicializa a flag de Dev se não existir
    if not query_db("SELECT id FROM dev_flag WHERE id = 1", one=True):
        print("Inicializando flag de Dev (Cargo 5)...")
        execute_db("INSERT INTO dev_flag (id, is_activated) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING")
        print("Flag inicializada.")

    print("Iniciando servidor Flask...")
    print(f"✅ Gemini AI: {'DISPONÍVEL' if GEMINI_AVAILABLE else 'INDISPONÍVEL'}")
    print(f"✅ Banco de Dados: {'CONECTADO' if get_db_connection() else 'ERRO'}")
    app.run(debug=True, port=5000)