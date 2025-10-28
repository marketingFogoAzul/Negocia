import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import re
import google.generativeai as genai

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
        """Sistema de permissão granular (Cargos 1-5 são 'admin')"""
        if self.role == 5: 
            return True # Dev (pode tudo)
        
        if self.role == 4: # Junior
            return permission not in ['promote_to_admin'] # Não pode promover admin
            
        if self.role == 3: # MKT/TI
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product', 
                'access_review', 'view_admin_panel', 'promote_to_junior', 'view_logs',
                'view_all_negotiations', 'close_chat', 'view_general_attendance'
            ]
            
        if self.role == 2: # Teste
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product',
                'access_review', 'view_admin_panel', 'promote_to_junior', 'view_logs',
                'view_all_negotiations', 'close_chat'
            ]
            
        if self.role == 1: # Vendedor
            return permission in [
                'view_chat', 'assume_negotiation', 'access_review', 'view_admin_panel',
                'close_chat'
            ]
            
        if self.role == 0: # Consumidor
            return permission in ['view_chat']
            
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
def role_required(min_role=1):
    """Verifica se o usuário tem o cargo MÍNIMO (1-5)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: 
                return login_manager.unauthorized()
            if current_user.role < min_role:
                flash("Você não tem permissão para acessar esta página.", "danger")
                return redirect(url_for('login')) 
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission):
    """Verifica se o usuário tem uma permissão específica"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: 
                return login_manager.unauthorized()
            if not current_user.can(permission): 
                abort(403) # Proibido
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
            if cur.rowcount == 0: # Garante que só seja ativado uma vez
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
        context = """
        Você é um assistente de vendas da empresa ZIPBUM Negocia. Seja educado, profissional e 
        focado em ajudar o cliente a escolher um produto e a quantidade.
        NÃO fale sobre cores ou entrega. O fluxo é apenas Produto -> Quantidade -> Valor.
        """
        
        if product_info:
            context += f"\n\nInformações do produto em discussão: {product_info}"
        
        if chat_history:
            context += "\n\nHistórico recente da conversa:"
            for msg in chat_history[-6:]:  # Últimas 6 mensagens
                role = "Usuário" if msg['sender_type'] == 'user' else "Assistente"
                context += f"\n{role}: {msg['text']}"
        
        prompt = f"{context}\n\nUsuário: {user_message}\nAssistente:"
        
        response = gemini_model.generate_content(prompt)
        return response.text.strip()
        
    except Exception as e:
        print(f"Erro ao chamar Gemini AI: {e}")
        return "Desculpe, ocorreu um erro ao processar sua mensagem. Por favor, tente novamente."

# --- ROTAS DE PÁGINAS (VIEW/CONTROLLER) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role >= 1:
            # CORREÇÃO: Redireciona admin para 'Meus Atendimentos'
            return redirect(url_for('admin_my_negotiations'))
        else:
            return redirect(url_for('new_chat_page'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = query_db("SELECT id, name, email, password_hash, role FROM users WHERE email = %s", (email,), one=True)
        
        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['name'], user_data['email'], user_data['role'])
            login_user(user, remember=True)
            session.pop('chat_state', None)
            log_action(user, 'LOGIN')
            
            if user.role >= 1:
                # CORREÇÃO: Redireciona admin para 'Meus Atendimentos'
                return redirect(url_for('admin_my_negotiations'))
            else:
                return redirect(url_for('new_chat_page'))
        else:
            flash('E-mail ou senha inválidos!', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.role >= 1:
            return redirect(url_for('admin_my_negotiations'))
        else:
            return redirect(url_for('new_chat_page'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not name or not email or not password or password != confirm_password or len(password) < 6:
            flash('Verifique os campos. As senhas devem coincidir e ter no mínimo 6 caracteres.', 'danger')
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
            return redirect(url_for('new_chat_page'))
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

def get_recent_chats(user_id):
    """Busca os chats recentes do usuário para a sidebar."""
    query = """
        SELECT c.id, c.status, c.created_at, p.name as product_name
        FROM chats c
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.user_id = %s
        ORDER BY c.created_at DESC
        LIMIT 10
    """
    return query_db(query, (user_id,)) or []

@app.route('/')
@app.route('/home')
@login_required
def home():
    """Redireciona o usuário para o local correto."""
    if current_user.role >= 1:
        # Admin vai para "Meus Atendimentos"
        return redirect(url_for('admin_my_negotiations'))
    else:
        # Consumidor vai para "Novo Chat"
        return redirect(url_for('new_chat_page'))

@app.route('/chat') # Rota principal do chat
@login_required
def new_chat_page():
    """Renderiza a página de chat vazia (novo chat)."""
    session.pop('chat_state', None)
    session.pop('current_chat_id', None)
    session.pop('negotiation_data', None)
    
    recent_chats = get_recent_chats(current_user.id)
    
    return render_template('chat.html', 
                         recent_chats=recent_chats,
                         chat_id=None,
                         chat_history=None,
                         chat_data=None # Indica um novo chat
                         )

@app.route('/chat/<int:chat_id>')
@login_required
def existing_chat_page(chat_id):
    """Renderiza um chat existente."""
    
    chat_data = query_db("""
        SELECT c.*, u.name as user_name, u.email as user_email 
        FROM chats c 
        LEFT JOIN users u ON c.user_id = u.id 
        WHERE c.id = %s
    """, (chat_id,), one=True)
    
    if not chat_data: 
        abort(404)
    
    # Verifica permissão (Dono do chat ou Admin/Vendedor)
    if chat_data['user_id'] != current_user.id and current_user.role < 1:
        abort(403) # Proibido
        
    # Vendedor (cargo 1) só pode ver se for dele
    if current_user.role == 1 and chat_data['assigned_to'] != current_user.id:
        abort(403)
    
    history = query_db("""
        SELECT m.sender_type, m.text, m.timestamp, u.name as sender_name
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id AND (m.sender_type = 'admin' OR m.sender_type = 'user')
        WHERE m.chat_id = %s 
        ORDER BY m.timestamp ASC
    """, (chat_id,))
    
    recent_chats = get_recent_chats(current_user.id)
    
    session.pop('chat_state', None)
    return render_template('chat.html', 
                         chat_data=chat_data, 
                         chat_history=history or [], 
                         chat_id=chat_id,
                         recent_chats=recent_chats)

# --- PAINEL ADMINISTRATIVO (NOVAS ROTAS) ---

@app.route('/admin')
@login_required
@role_required(min_role=1)
def admin_dashboard():
    """NOVO: Dashboard individual e global."""
    
    # Stats Individuais (Meus)
    my_pending = query_db(
        "SELECT COUNT(id) as c FROM chats WHERE assigned_to = %s AND status = 'assumed'", 
        (current_user.id,), one=True
    )['c'] or 0
    
    my_completed = query_db(
        "SELECT COUNT(id) as c FROM chats WHERE assigned_to = %s AND status = 'completed'", 
        (current_user.id,), one=True
    )['c'] or 0
    
    # Stats Globais (Para todos os admins)
    available = query_db(
        "SELECT COUNT(id) as c FROM chats WHERE status = 'pending_review'", one=True
    )['c'] or 0

    stats = {
        'my_pending': my_pending,
        'my_completed': my_completed,
        'available': available
    }
    
    return render_template('admin/admin_dashboard.html', stats=stats)

@app.route('/admin/status')
@login_required
@role_required(min_role=1)
def admin_status():
    """NOVO: Página de Status do Sistema."""
    gemini_status = "online" if GEMINI_AVAILABLE else "offline"
    db_status = "online" if get_db_connection() else "offline"
    
    return render_template('admin/admin_status.html', 
                           gemini_status=gemini_status, 
                           db_status=db_status)

@app.route('/admin/users')
@login_required
@permission_required('promote_to_junior')
def admin_users():
    """MODIFICADO: Gerenciar Usuários com busca."""
    dev_activated = check_dev_flag()
    search_query = request.args.get('q', '').strip()
    
    base_query = "SELECT id, name, email, role, created_at FROM users"
    conditions = []
    args = []

    if search_query:
        search_term_like = f"%{search_query}%"
        try:
            # Tenta buscar por ID ou Cargo
            search_int = int(search_query)
            conditions.append("(name ILIKE %s OR email ILIKE %s OR id = %s OR role = %s)")
            args.extend([search_term_like, search_term_like, search_int, search_int])
        except ValueError:
            # Busca por Nome ou Email
            conditions.append("(name ILIKE %s OR email ILIKE %s)")
            args.extend([search_term_like, search_term_like])
    
    if dev_activated:
        conditions.append("role != 5") # Esconde o cargo 5
        
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY role DESC, name ASC"
    
    users = query_db(base_query, tuple(args)) or []
    
    return render_template('admin/admin_users.html', 
                           users=users, 
                           dev_activated=dev_activated, 
                           search_query=search_query)

@app.route('/admin/products')
@login_required
@permission_required('insert_product')
def admin_products():
    """MODIFICADO: Gerenciar Produtos com busca."""
    search_query = request.args.get('q', '').strip()
    
    query = "SELECT * FROM products"
    args = ()
    
    if search_query:
        query += " WHERE name ILIKE %s OR code ILIKE %s"
        search_term_like = f"%{search_query}%"
        args = (search_term_like, search_term_like)
        
    query += " ORDER BY name ASC"
    
    products = query_db(query, args) or []
    return render_template('admin/admin_products.html', 
                           products=products, 
                           search_query=search_query)

@app.route('/admin/negotiations')
@login_required
@permission_required('view_all_negotiations') # Cargos 2+
def admin_negotiations():
    """MODIFICADO: Histórico de Conversas (Geral, View-Only)."""
    search_query = request.args.get('q', '').strip()
    
    base_query = """
        SELECT c.id, c.status, c.created_at, u.name as user_name, u.email as user_email, 
               a.name as assigned_admin, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN users a ON c.assigned_to = a.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
    """
    
    args = []
    conditions = []

    if search_query:
        search_term_like = f"%{search_query}%"
        search_condition_text = "(u.name ILIKE %s OR u.email ILIKE %s OR a.name ILIKE %s)"
        args.extend([search_term_like, search_term_like, search_term_like])
        
        try:
            chat_id_int = int(search_query)
            search_condition = f"({search_condition_text} OR c.id = %s)"
            args.append(chat_id_int)
        except ValueError:
            search_condition = search_condition_text
        
        conditions.append(search_condition)

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY c.created_at DESC"
    
    negotiations = query_db(base_query, tuple(args)) or []
    
    return render_template('admin/admin_negotiations.html', 
                           negotiations=negotiations, 
                           search_query=search_query)

@app.route('/admin/my_negotiations')
@login_required
@role_required(min_role=1)
def admin_my_negotiations():
    """NOVO: Meus Atendimentos (Individual)."""
    
    # Chats "Em Andamento" (Assumidos por mim)
    pending = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.assigned_to = %s AND c.status IN ('assumed', 'manual_override')
        ORDER BY c.created_at DESC
    """, (current_user.id,)) or []
    
    # Chats "Fechados" (Fechados por mim)
    completed = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.assigned_to = %s AND c.status = 'completed'
        ORDER BY c.created_at DESC
    """, (current_user.id,)) or []
    
    return render_template('admin/my_negotiations.html', pending_chats=pending, completed_chats=completed)


@app.route('/admin/all_negotiations')
@login_required
@permission_required('view_general_attendance') # Cargos 3, 4, 5
def admin_all_negotiations():
    """NOVO: Atendimentos (Geral) - Visível para 3, 4, 5."""
    
    # Agrupa todos os atendimentos por admin
    admins_with_chats = query_db("""
        SELECT a.id, a.name, a.role, COUNT(c.id) as chat_count
        FROM users a
        JOIN chats c ON c.assigned_to = a.id
        WHERE a.role >= 1
        GROUP BY a.id
        ORDER BY a.name
    """) or []
    
    # Pega os chats recentes para cada admin (exemplo, pode ser mais complexo)
    all_chats = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, c.assigned_to
        FROM chats c
        JOIN users u ON c.user_id = u.id
        WHERE c.assigned_to IS NOT NULL
        ORDER BY c.created_at DESC
    """) or []

    # Estrutura dados para o template
    admin_data = {}
    for admin in admins_with_chats:
        admin_data[admin['id']] = {
            'name': admin['name'],
            'role': admin['role'],
            'chats': []
        }
    
    for chat in all_chats:
        if chat['assigned_to'] in admin_data:
            admin_data[chat['assigned_to']]['chats'].append(chat)

    return render_template('admin/all_negotiations.html', admin_data=admin_data)


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
    
    total_logs = query_db("SELECT COUNT(id) as c FROM audit_log", one=True)['c'] or 0
    total_pages = (total_logs // limit) + (1 if total_logs % limit > 0 else 0)
    
    return render_template('admin/admin_logs.html', 
                           logs=logs, 
                           current_page=page, 
                           total_pages=total_pages)

# --- API DE AUTENTICAÇÃO (Sem mudanças) ---
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
    
    return jsonify({
        'success': True, 
        'message': 'Registro bem-sucedido!', 
        'redirect': url_for('new_chat_page')
    })

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
        user = User(user_data['id'], user_data['name'], user_data['email'], user_data['role'])
        login_user(user)
        session.pop('chat_state', None)
        log_action(user, 'LOGIN')
        
        # CORREÇÃO: Redireciona admin para 'Meus Atendimentos'
        redirect_url = url_for('admin_my_negotiations') if user.role >= 1 else url_for('new_chat_page')
        return jsonify({
            'success': True, 
            'message': 'Login bem-sucedido!',
            'redirect': redirect_url
        })
    else:
        log_action(None, 'LOGIN_FAILED', details=f"Tentativa falha (senha incorreta): {email}")
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

# --- API DO CHAT (LÓGICA PRINCIPAL) ---
def save_message(chat_id, sender_type, text, sender_id=None):
    """Função helper para salvar qualquer mensagem no DB."""
    return execute_db(
        "INSERT INTO messages (chat_id, sender_type, sender_id, text) VALUES (%s, %s, %s, %s)",
        (chat_id, sender_type, sender_id, text)
    )

def process_chat_state_machine(user_message, user):
    """Processa a mensagem do usuário (IA - Máquina de Estado Simplificada)."""
    
    # CORREÇÃO: Pega estado da sessão, ou inicia 'START'
    state = session.get('chat_state', 'START')
    chat_id = session.get('current_chat_id')
    negotiation = session.get('negotiation_data', {})
    bot_response = "Desculpe, não entendi."

    if not chat_id:
        # Cria um novo chat
        new_chat_id = execute_db(
            "INSERT INTO chats (user_id, status) VALUES (%s, 'active') RETURNING id", 
            (user.id,),
            returning_id=True
        )
        if not new_chat_id:
            return {'sender_type': 'bot', 'text': 'Erro: Não consegui iniciar um novo chat.', 'chat_id': None}
        
        chat_id = new_chat_id
        session['current_chat_id'] = chat_id
        log_action(user, 'CHAT_START', details=f"Iniciou chat ID: {chat_id}")
        
        # CORREÇÃO: A primeira mensagem é a saudação do bot
        bot_response = f"Olá {user.name}, Qual produto você deseja verificar negociação?"
        session['chat_state'] = 'AWAITING_PRODUCT' # Próximo estado
        
        save_message(chat_id, 'user', user_message, user.id) # Salva a msg do user
        save_message(chat_id, 'bot', bot_response, None) # Salva a 1a msg do bot
        
        return {
            'sender_type': 'bot', 
            'text': bot_response, 
            'chat_id': chat_id,
            'chat_status': 'active'
        }

    # Se o chat já existe, salva a mensagem do usuário
    save_message(chat_id, 'user', user_message, user.id)

    # --- LÓGICA DA MÁQUINA DE ESTADO (SIMPLIFICADA) ---
    if state == 'AWAITING_PRODUCT':
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
            bot_response = get_gemini_response(user_message, None, None)
            state = 'AWAITING_PRODUCT' # Mantém no estado

    elif state == 'AWAITING_QUANTITY':
        try:
            quantity = int(re.findall(r'\d+', user_message)[0]) # Tenta extrair número
            
            if 0 < quantity <= negotiation.get('max_stock', 0):
                negotiation['quantity'] = quantity
                total_value = negotiation['product_price'] * negotiation['quantity']
                negotiation['total_value'] = total_value
                
                bot_response = (
                    f"Certo! Sua proposta é:\n"
                    f"Produto: {negotiation['product_name']} (Qtd: {negotiation['quantity']})\n"
                    f"Valor Total: R$ {total_value:.2f}\n\n"
                    "Se estiver tudo certo, clique em 'Solicitar Revisão' abaixo para um de nossos vendedores analisar."
                )
                
                state = 'AWAITING_REVIEW' # Estado final da IA
                proposal_json = json.dumps(negotiation)
                
                execute_db(
                    "UPDATE chats SET proposal_data = %s WHERE id = %s", 
                    (proposal_json, chat_id)
                )
            else:
                bot_response = f"Quantidade inválida. Temos {negotiation.get('max_stock', 0)} em estoque."
                state = 'AWAITING_QUANTITY'
                
        except (ValueError, KeyError, IndexError):
            bot_response = "Por favor, informe apenas o número de unidades."
            state = 'AWAITING_QUANTITY'

    elif state == 'AWAITING_REVIEW':
        # A IA já deu o preço. Agora só usa Gemini para respostas genéricas.
        chat_history = query_db(
            "SELECT sender_type, text FROM messages WHERE chat_id = %s ORDER BY timestamp DESC LIMIT 6",
            (chat_id,)
        )
        bot_response = get_gemini_response(user_message, chat_history, json.dumps(negotiation))
        state = 'AWAITING_REVIEW' # Permanece aqui

    else: # Estado 'START' (caso a primeira msg não seja tratada)
        bot_response = f"Olá {user.name}, Qual produto você deseja verificar negociação?"
        state = 'AWAITING_PRODUCT'


    session['chat_state'] = state
    session['negotiation_data'] = negotiation
    save_message(chat_id, 'bot', bot_response, None)
    
    return {
        'sender_type': 'bot', 
        'text': bot_response, 
        'chat_id': chat_id, 
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
            # Se o chat não está ativo, salva a msg do user mas o bot não responde
            save_message(chat_id, 'user', user_message, user.id) 
            bot_response = "Este chat está sendo analisado por um vendedor. Por favor, aguarde a resposta."
            if chat['status'] == 'completed':
                bot_response = "Esta negociação foi encerrada."
            
            # Envia resposta 'falsa' do bot
            return jsonify({
                'sender_type': 'system', # Mensagem do sistema
                'text': bot_response, 
                'chat_status': chat['status']
            })

    # Comando secreto
    if user_message == "Qazxcvbnmlp7@":
        if check_dev_flag(): 
            response_text = "Comando já utilizado."
        else:
            success = activate_dev_flag(user)
            response_text = "MODO DESENVOLVEDOR ATIVADO." if success else "Comando já utilizado por outro."
        
        if chat_id:
            save_message(chat_id, 'user', '*** COMANDO SECRETO ***', user.id)
            save_message(chat_id, 'bot', response_text, None)
        
        return jsonify({'sender_type': 'bot', 'text': response_text, 'chat_id': chat_id})

    # Processa a mensagem pela máquina de estados
    response = process_chat_state_machine(user_message, user)
    return jsonify(response)

@app.route('/api/chat/request_review/<int:chat_id>', methods=['POST'])
@login_required
def api_request_review(chat_id):
    """CORREÇÃO: Usuário clica no botão. Só funciona UMA VEZ."""
    
    chat = query_db("SELECT id, user_id, status, review_requested FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat or chat['user_id'] != current_user.id:
        return jsonify({'success': False, 'message': 'Chat não encontrado ou não autorizado.'}), 404
    
    # CORREÇÃO: Verifica a flag 'review_requested'
    if chat['review_requested']:
        return jsonify({'success': False, 'message': 'Revisão já foi solicitada para este chat.'}), 400
        
    if chat['status'] != 'active':
         return jsonify({'success': False, 'message': 'Este chat não pode ser enviado para revisão.'}), 400

    # Seta o status e a flag 'review_requested'
    success = execute_db(
        "UPDATE chats SET status = 'pending_review', review_requested = TRUE WHERE id = %s", 
        (chat_id,)
    )
    
    if success:
        log_action(current_user, 'REQUEST_REVIEW', details=f"Usuário solicitou revisão para o chat ID: {chat_id}")
        bot_response = "Sua solicitação foi enviada! Um de nossos vendedores assumirá esta conversa em breve."
        save_message(chat_id, 'system', bot_response, None) # Salva como system
        
        return jsonify({
            'success': True, 
            'message': bot_response, 
            'sender_type': 'system', # Envia como system
            'chat_status': 'pending_review'
        })
    else:
        return jsonify({'success': False, 'message': 'Erro ao solicitar revisão.'}), 500

@app.route('/api/chat/admin_message/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_chat_admin_message(chat_id):
    """Admin (vendedor) envia uma mensagem."""
    data = request.json
    admin_message = data.get('message', '').strip()
    
    if not admin_message: 
        return jsonify({'error': 'Mensagem vazia'}), 400
    
    admin_user = current_user
    chat = query_db("SELECT id, user_id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat: 
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    # Vendedor (cargo 1) só pode responder se o chat for dele
    if admin_user.role == 1 and chat['assigned_to'] != admin_user.id:
        return jsonify({'success': False, 'message': 'Você não pode responder este chat.'}), 403
    
    if chat['status'] == 'completed':
        return jsonify({'success': False, 'message': 'Este chat já foi encerrado.'}), 400
        
    # Se o chat estava "pendente", o admin assume automaticamente ao responder
    if chat['status'] == 'pending_review':
        execute_db(
            "UPDATE chats SET status = 'assumed', assigned_to = %s WHERE id = %s", 
            (admin_user.id, chat_id)
        )
        log_action(admin_user, 'ASSUME_CHAT', details=f"Assumiu (respondendo) chat ID: {chat_id}")
        
    save_message(chat_id, 'admin', admin_message, admin_user.id)
    
    return jsonify({
        'success': True, 
        'sender_type': 'admin', 
        'text': admin_message, 
        'sender_name': admin_user.name,
        'chat_status': 'assumed' # Garante que o status mude no front
    })

@app.route('/api/chat/disable_ia/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_disable_ia(chat_id):
    chat = query_db("SELECT id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    if not chat:
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    # Vendedor (cargo 1) só pode desativar IA do seu próprio chat
    if current_user.role == 1 and chat['assigned_to'] != current_user.id:
        return jsonify({'success': False, 'message': 'Não autorizado.'}), 403

    if chat['status'] == 'completed':
        return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400
    
    success = execute_db(
        "UPDATE chats SET status = 'manual_override' WHERE id = %s", (chat_id,)
    )
    
    if success:
        log_action(current_user, 'DISABLE_IA', details=f"Desativou IA do chat ID: {chat_id}")
        msg_text = f"{current_user.name} desativou a IA. Atendimento 100% manual."
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
        
    # Vendedor (cargo 1) só pode fechar o seu
    if current_user.role == 1 and chat['assigned_to'] != current_user.id:
        return jsonify({'success': False, 'message': 'Você não tem permissão para encerrar este chat.'}), 403

    success = execute_db(
        "UPDATE chats SET status = 'completed' WHERE id = %s", (chat_id,)
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
            return jsonify({'success': False, 'message': 'Este código (SKU) já existe.'}), 409
        
        success = execute_db(
            "INSERT INTO products (code, name, price, stock, colors) VALUES (%s, %s, %s, %s, %s)", 
            (code, name, price, stock, colors if colors else None)
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
    if not product:
        return jsonify({'success': False, 'message': 'Produto não encontrado.'}), 404

    product_name = f"{product['name']} ({product['code']})"
    success = execute_db("DELETE FROM products WHERE id = %s", (product_id,))
    
    if success:
        log_action(current_user, 'PRODUCT_REMOVE', details=f"Produto: {product_name}")
        return jsonify({'success': True, 'message': 'Produto removido.'})
    else: 
        return jsonify({'success': False, 'message': 'Erro ao remover.'}), 500

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
    
    if new_role == 5 or (admin_role != 5 and new_role == 4 and not current_user.can('promote_to_admin')):
         return jsonify({'success': False, 'message': 'Permissão negada para este nível.'}), 403

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
    """Admin assume um chat que estava 'pending_review'."""
    admin_user = current_user
    chat = query_db("SELECT status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    
    if not chat: 
        return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    
    if chat['status'] != 'pending_review':
        return jsonify({'success': False, 'message': 'Este chat não está pendente de revisão.'}), 409

    success = execute_db(
        "UPDATE chats SET status = 'assumed', assigned_to = %s WHERE id = %s", 
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
    app.run(debug=True, port=5000)