import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import re
import google.generativeai as genai

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, jsonify, session, redirect, url_for, flash, abort, make_response
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
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'fallback_secret_key_if_not_set') # Adicionado fallback
DATABASE_URL = os.getenv('DATABASE_URL')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# Configuração do Gemini
try:
    if not GEMINI_API_KEY:
        raise ValueError("API Key do Gemini não encontrada no .env")
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-pro')
    GEMINI_AVAILABLE = True
    print("✅ Gemini AI configurado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao configurar Gemini: {e}")
    GEMINI_AVAILABLE = False
    gemini_model = None

# Configuração do Banco de Dados
if not DATABASE_URL:
    print("❌ ERRO CRÍTICO: DATABASE_URL não definida no arquivo .env!")
    # Você pode querer abortar a aplicação aqui em um ambiente real
    # import sys
    # sys.exit(1)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "warning" # Usar warning para a mensagem

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
            # Pode tudo, exceto promover outros para admin (4 ou 5)
             return permission not in ['promote_to_admin']

        if self.role == 3: # MKT/TI
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product',
                'access_review', 'view_admin_panel', 'promote_to_junior', 'view_logs',
                'view_all_negotiations', 'close_chat', 'view_general_attendance'
            ]

        if self.role == 2: # Teste
             # Pode quase tudo relacionado a negociações e produtos, mas menos permissões de usuário
            return permission in [
                'view_chat', 'assume_negotiation', 'insert_product', 'remove_product',
                'access_review', 'view_admin_panel', 'view_logs',
                'view_all_negotiations', 'close_chat'
            ]

        if self.role == 1: # Vendedor
            # Focado em atender chats
            return permission in [
                'view_chat', 'assume_negotiation', 'access_review', 'view_admin_panel', # Acesso básico ao painel
                'close_chat' # Pode fechar SEUS chats
            ]

        if self.role == 0: # Consumidor
            return permission in ['view_chat']

        return False

@login_manager.user_loader
def load_user(user_id):
    """Carrega o usuário da sessão"""
    conn = get_db_connection()
    if not conn:
        print("Erro crítico: Não foi possível conectar ao DB para carregar usuário.")
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
        print(f"Erro ao carregar usuário ID {user_id}: {e}")
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
                # Se for AJAX, retorna erro, senão redireciona
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    abort(403) # Forbidden
                return login_manager.unauthorized()
            if current_user.role < min_role:
                # Se for AJAX, retorna erro, senão redireciona
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    abort(403) # Forbidden
                flash("Acesso negado. Permissão insuficiente.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission):
    """Verifica se o usuário tem uma permissão específica"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                 # Se for AJAX, retorna erro, senão redireciona
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    abort(401) # Unauthorized
                return login_manager.unauthorized()
            if not hasattr(current_user, 'can') or not current_user.can(permission):
                print(f"WARN: Usuário {current_user.id} tentou acessar '{permission}' sem permissão.")
                abort(403) # Forbidden (AJAX ou não)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Função helper para renderizar parcial ou completo ---
def render_admin_template(template_name_or_list, **context):
    """Renderiza o template completo ou apenas o bloco 'content' para AJAX."""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Renderiza apenas o bloco de conteúdo para requisições AJAX
        # Usando um layout base mínimo para apenas incluir os blocos necessários
        context['is_partial'] = True
        base_template = "layout_partial.html"
    else:
        # Renderiza a página completa (herdando de layout_admin.html)
        context['is_partial'] = False
        base_template = "layout_admin.html"

    # Renderiza o template específico, que por sua vez herda do base_template correto
    return render_template(template_name_or_list, **context, base_template=base_template)


def get_db_connection():
    try:
        if not DATABASE_URL:
             print("ERRO FATAL: DATABASE_URL não está configurada.")
             return None
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        print(f"Erro crítico ao conectar no Neon DB: {e}")
        return None
    except Exception as e:
        print(f"Erro inesperado na conexão DB: {e}")
        return None


def query_db(query, args=(), one=False):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, args)
            # Verifica se precisa buscar dados (SELECT)
            if cur.description:
                result = cur.fetchone() if one else cur.fetchall()
                return result
            else:
                 # Se for INSERT/UPDATE/DELETE sem RETURNING, retorna None
                return None
    except psycopg2.Error as e:
        print(f"Erro de DB ao executar query: {e}")
        print(f"Query: {query}")
        print(f"Args: {args}")
        return None
    except Exception as e:
        print(f"Erro geral ao executar query: {e}")
        return None
    finally:
        if conn:
            conn.close()

def execute_db(query, args=(), returning_id=False):
    conn = get_db_connection()
    if not conn:
        return False if not returning_id else None # Retorna tipo consistente
    last_id = None
    success = False
    try:
        with conn.cursor() as cur:
            cur.execute(query, args)
            if returning_id:
                # Tenta buscar o ID retornado (funciona com RETURNING id)
                row = cur.fetchone()
                if row:
                    last_id = row[0]
            conn.commit()
            success = True
    except psycopg2.Error as e:
        print(f"Erro de DB ao executar comando: {e}")
        print(f"Query: {query}")
        print(f"Args: {args}")
        conn.rollback() # Desfaz a transação em caso de erro
    except Exception as e:
        print(f"Erro geral ao executar comando: {e}")
        conn.rollback()
    finally:
        if conn:
            conn.close()

    if returning_id:
        return last_id # Retorna o ID ou None
    else:
        return success # Retorna True ou False

# --- FUNÇÕES DE LOG E DEV FLAG ---
def log_action(user, action, details=None, target_user_id=None):
    try:
        user_id = user.id if user and hasattr(user, 'id') else None
        user_email = user.email if user and hasattr(user, 'email') else 'System'
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
    # Garante que apenas usuários autenticados possam tentar
    if not user or not hasattr(user, 'id'):
        return False

    conn = get_db_connection()
    if not conn:
        return False
    activated = False
    try:
        with conn.cursor() as cur:
            # Tenta ativar a flag apenas se ela estiver FALSE
            cur.execute("UPDATE dev_flag SET is_activated = TRUE, activated_by_user_id = %s WHERE id = 1 AND is_activated = FALSE RETURNING id", (user.id,))
            result = cur.fetchone()
            if result: # Se a atualização retornou o ID, significa que funcionou
                # Promove o usuário para Dev (role 5)
                cur.execute("UPDATE users SET role = 5 WHERE id = %s", (user.id,))
                conn.commit()
                log_action(user, 'DEV_MODE_ACTIVATED', details="Comando secreto Qazxcvbnmlp7@ utilizado.")
                activated = True
            else:
                 # Se não retornou ID, a flag já estava TRUE, faz rollback
                conn.rollback()
                print(f"Usuário {user.id} tentou ativar flag Dev já ativa.")
                activated = False
    except psycopg2.Error as e:
        print(f"Erro DB ao ativar flag Dev: {e}")
        conn.rollback()
    except Exception as e:
        print(f"Erro geral ao ativar flag Dev: {e}")
        conn.rollback()
    finally:
        if conn:
            conn.close()
    return activated

# --- FUNÇÃO GEMINI AI ---
def get_gemini_response(user_message, chat_history=None, product_info=None):
    """Obtém resposta do Gemini AI baseada no contexto da conversa"""
    if not GEMINI_AVAILABLE or not gemini_model:
        print("WARN: Tentativa de chamar Gemini AI, mas não está disponível.")
        return "Desculpe, o serviço de IA está temporariamente indisponível."

    try:
        # --- Busca Filtros de IA ---
        all_filters = query_db("SELECT rule_type, content FROM ia_filters") or []
        prompt_rules = []
        blocked_words = []
        if all_filters:
            for f in all_filters:
                if f['rule_type'] == 'regra_prompt':
                    prompt_rules.append(f['content'])
                elif f['rule_type'] == 'palavra_bloqueada':
                    blocked_words.append(f['content'].lower())
        
        # --- Constrói o Contexto (System Prompt) ---
        context = """
        Você é um assistente de vendas da empresa ZIPBUM Negocia. Seja educado, profissional e
        focado em ajudar o cliente a escolher um produto e a quantidade.
        NÃO fale sobre cores ou entrega. O fluxo é apenas Produto -> Quantidade -> Valor.
        Se o usuário perguntar algo fora do escopo de vendas (produtos, quantidade, preço),
        responda educadamente que você só pode ajudar com negociações.
        """

        # Adiciona regras do DB
        if prompt_rules:
            context += "\n\nREGRAS ADICIONAIS IMPORTANTES:\n"
            for rule in prompt_rules:
                context += f"- {rule}\n"


        if product_info:
             # Formata melhor as infos do produto
            try:
                prod_data = json.loads(product_info)
                context += f"\n\nContexto do produto: Nome={prod_data.get('product_name', 'N/A')}, Preço Unitário=R${prod_data.get('product_price', 0):.2f}"
            except json.JSONDecodeError:
                 context += f"\n\nContexto do produto: {product_info}"


        if chat_history:
            context += "\n\nHistórico recente (máx 6):"
            # Inverte para pegar as últimas, depois inverte de novo para ordem cronológica
            for msg in reversed(chat_history[-6:]):
                role = "user" if msg['sender_type'] == 'user' else "model" # Gemini usa 'user' e 'model'
                # Prepara a estrutura de conteúdo do Gemini
                context += f"\n{role}: {msg['text']}" # Simplificado para prompt direto

        # Prepara o prompt final para o modelo
        full_prompt = f"{context}\n\nuser: {user_message}\nmodel:"

        # Chama a API Gemini
        response = gemini_model.generate_content(full_prompt)

        # Tratamento de segurança e resposta vazia
        if not response.candidates or not response.candidates[0].content.parts:
             print(f"WARN: Gemini retornou resposta vazia ou bloqueada. Prompt: {full_prompt}")
             return "Não consigo processar essa solicitação no momento. Você pode tentar reformular?"
        if response.candidates[0].finish_reason != 'STOP':
            print(f"WARN: Gemini finalizou com razão '{response.candidates[0].finish_reason}'.")
            # Pode retornar uma mensagem genérica ou a resposta parcial, se houver
            # return response.text.strip() if response.text else "Houve um problema ao gerar a resposta completa."
            return "Não consigo processar essa solicitação no momento. Você pode tentar reformular?"


        response_text = response.text.strip()

        # Filtra palavras bloqueadas na SAÍDA
        if blocked_words:
            response_text_lower = response_text.lower()
            for word in blocked_words:
                if word in response_text_lower:
                    # Se uma palavra bloqueada for encontrada, substitui a msg
                    log_action(None, 'IA_FILTER_TRIGGERED', details=f"IA tentou dizer: {word}")
                    response_text = "Desculpe, não posso fornecer informações sobre esse tópico específico. Posso ajudar com mais alguma coisa?"
                    break # Para no primeiro bloqueio
        
        return response_text

    except Exception as e:
        print(f"Erro CRÍTICO ao chamar Gemini AI: {e}")
        # Considerar logar o 'full_prompt' aqui para debug
        return "Desculpe, ocorreu um erro interno ao processar sua mensagem. Tente novamente mais tarde."

# --- ROTAS DE PÁGINAS (VIEW/CONTROLLER) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Se já logado, redireciona para a página apropriada
        return redirect(url_for('new_chat_page'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('E-mail e senha são obrigatórios.', 'danger')
            return render_template('login.html')

        user_data = query_db("SELECT id, name, email, password_hash, role FROM users WHERE email = %s", (email,), one=True)

        # Verifica se o usuário existe e a senha está correta
        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['name'], user_data['email'], user_data['role'])
            # Usa remember=True para manter o login persistente
            login_user(user, remember=True)
            # Limpa qualquer estado de chat anterior
            session.pop('chat_state', None)
            session.pop('current_chat_id', None)
            session.pop('negotiation_data', None)
            log_action(user, 'LOGIN')
            flash('Login realizado com sucesso!', 'success')

            # Todos os usuários são redirecionados para a página principal do chat
            return redirect(url_for('new_chat_page'))
        else:
            log_action(None, 'LOGIN_FAILED', details=f"Tentativa falha: {email}")
            flash('E-mail ou senha inválidos!', 'danger')
            # Não redireciona, apenas re-renderiza a página de login com a flash message

    # Se GET ou se login falhou, mostra a página de login
    return render_template('login.html')

# CORREÇÃO: Assegura que a definição de /register esteja separada
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        # Se já logado, redireciona
        return redirect(url_for('new_chat_page'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validações
        if not name or not email or not password:
            flash('Todos os campos são obrigatórios!', 'danger')
        elif password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
        elif len(password) < 6:
            flash('A senha deve ter pelo menos 6 caracteres!', 'danger')
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Formato de e-mail inválido!', 'danger')
        elif query_db("SELECT id FROM users WHERE email = %s", (email,), one=True):
            flash('Este e-mail já está em uso!', 'danger')
        else:
            # Se todas as validações passaram
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user_id = execute_db(
                "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 0) RETURNING id",
                (name, email, hashed_password),
                returning_id=True
            )

            if user_id:
                user = User(id=user_id, name=name, email=email, role=0)
                login_user(user) # Loga o novo usuário automaticamente
                log_action(user, 'REGISTER', details=f"Nova conta criada: {email}")
                flash('Conta criada com sucesso! Você já está logado.', 'success')
                return redirect(url_for('new_chat_page')) # Redireciona para o chat
            else:
                flash('Erro interno ao criar conta. Tente novamente.', 'danger')

        # Se houve erro de validação ou DB, re-renderiza o formulário
        return render_template('register.html')

    # Se for método GET, apenas mostra o formulário
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    log_action(current_user, 'LOGOUT')
    logout_user()
    session.clear()
    flash("Você saiu com sucesso.", "info")

    # Criar a resposta de redirecionamento
    response = make_response(redirect(url_for('login')))

    # Adicionar headers para forçar o no-cache
    # Isso impede que o navegador use uma resposta antiga
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

def get_recent_chats(user_id):
    """Busca os chats recentes do usuário para a sidebar."""
    # Retorna APENAS os chats do usuário logado (role 0)
    # ou TODOS os chats se for admin (role >= 1) - limitado a 15 mais recentes
    query = """
        SELECT c.id, c.status, c.created_at, p.name as product_name, u.name as user_name
        FROM chats c
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        JOIN users u ON c.user_id = u.id
    """
    args = ()
    if current_user.is_authenticated and current_user.role == 0: # Check authentication here
         query += " WHERE c.user_id = %s"
         args = (user_id,)

    query += " ORDER BY c.created_at DESC LIMIT 15"
    return query_db(query, args) or []

@app.route('/')
@app.route('/home')
@login_required
def home():
    """Redireciona o usuário para o local correto."""
    # Todos os usuários são redirecionados para a página principal do chat
    return redirect(url_for('new_chat_page'))

@app.route('/chat') # Rota principal do chat
@login_required
def new_chat_page():
    """Renderiza a página de chat vazia (novo chat)."""
    session.pop('chat_state', None)
    session.pop('current_chat_id', None)
    session.pop('negotiation_data', None)

    recent_chats = get_recent_chats(current_user.id)

    # Usa layout_chat.html
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
        flash("Chat não encontrado.", "danger")
        return redirect(url_for('home')) # Redireciona se o chat não existe

    # Verifica permissão
    is_owner = chat_data['user_id'] == current_user.id
    is_admin = current_user.role >= 1
    is_assigned_admin = is_admin and chat_data.get('assigned_to') == current_user.id

    # Regras de acesso:
    # - Dono do chat (role 0) sempre pode ver.
    # - Vendedor (role 1) pode ver SE for atribuído a ele OU se estiver pendente.
    # - Admins (role 2+) podem ver qualquer chat.
    can_view = False
    if is_owner:
        can_view = True
    elif is_admin:
        if current_user.role >= 2: # Admins 2+
            can_view = True
        elif current_user.role == 1: # Vendedor
            if is_assigned_admin or chat_data['status'] == 'pending_review':
                 can_view = True

    if not can_view:
        flash("Você não tem permissão para acessar este chat.", "danger")
        return redirect(url_for('home'))


    history = query_db("""
        SELECT m.sender_type, m.text, m.timestamp, u.name as sender_name
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id AND (m.sender_type = 'admin' OR m.sender_type = 'user')
        WHERE m.chat_id = %s
        ORDER BY m.timestamp ASC
    """, (chat_id,))

    recent_chats = get_recent_chats(current_user.id)

    # Limpa estado da sessão anterior para evitar conflitos
    session.pop('chat_state', None)
    session.pop('current_chat_id', None)
    session.pop('negotiation_data', None)

    # Usa layout_chat.html
    return render_template('chat.html',
                         chat_data=chat_data,
                         chat_history=history or [],
                         chat_id=chat_id,
                         recent_chats=recent_chats)

# --- PAINEL ADMINISTRATIVO ---

# CORREÇÃO: Assegura que a definição da rota esteja correta e separada
@app.route('/admin') # Rota para o Dashboard
@app.route('/admin/dashboard') # Rota alternativa explícita
@login_required
@role_required(min_role=1)
def admin_dashboard():
    """Dashboard individual e global."""

    my_pending_count = 0
    my_completed_count = 0
    if current_user.is_authenticated and current_user.role >= 1:
        my_pending = query_db(
            "SELECT COUNT(id) as c FROM chats WHERE assigned_to = %s AND status IN ('assumed', 'manual_override')",
            (current_user.id,), one=True
        )
        my_pending_count = my_pending['c'] if my_pending else 0

        my_completed = query_db(
            "SELECT COUNT(id) as c FROM chats WHERE assigned_to = %s AND status = 'completed'",
            (current_user.id,), one=True
        )
        my_completed_count = my_completed['c'] if my_completed else 0

    available = query_db(
        "SELECT COUNT(id) as c FROM chats WHERE status = 'pending_review'", one=True
    )
    available_count = available['c'] if available else 0

    stats = {
        'my_pending': my_pending_count,
        'my_completed': my_completed_count,
        'available': available_count
    }

    # Utiliza a função helper para renderizar (parcial ou completo)
    return render_admin_template('admin/admin_dashboard.html', stats=stats)


@app.route('/admin/status')
@login_required
@role_required(min_role=1)
def admin_status():
    """Página de Status do Sistema."""
    gemini_status = "online" if GEMINI_AVAILABLE else "offline"
    db_conn = get_db_connection()
    db_status = "online" if db_conn else "offline"
    if db_conn:
        db_conn.close()

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_status.html',
                           gemini_status=gemini_status,
                           db_status=db_status)

@app.route('/admin/users')
@login_required
@permission_required('promote_to_junior') # Garante que só quem pode promover acesse
def admin_users():
    """Gerenciar Usuários com busca."""
    dev_activated = check_dev_flag()
    search_query = request.args.get('q', '').strip()

    base_query = "SELECT id, name, email, role, created_at FROM users"
    conditions = []
    args = []

    # Permite buscar por Nome, Email, ID ou Cargo (número)
    if search_query:
        search_term_like = f"%{search_query}%"
        try:
            search_int = int(search_query)
            # Busca ID ou Role se for número
            conditions.append("(name ILIKE %s OR email ILIKE %s OR id = %s OR role = %s)")
            args.extend([search_term_like, search_term_like, search_int, search_int])
        except ValueError:
            # Busca Nome ou Email se não for número
            conditions.append("(name ILIKE %s OR email ILIKE %s)")
            args.extend([search_term_like, search_term_like])

    # Admins não Dev não devem ver o Dev se a flag estiver ativa
    if current_user.role != 5 and dev_activated:
        conditions.append("role != 5")

    # Garante que admins só vejam/modifiquem usuários de cargo INFERIOR
    conditions.append("role < %s")
    args.append(current_user.role)


    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    base_query += " ORDER BY role DESC, name ASC"

    users = query_db(base_query, tuple(args)) or []

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_users.html',
                           users=users,
                           dev_activated=dev_activated,
                           search_query=search_query)

@app.route('/admin/products')
@login_required
@permission_required('insert_product') # Quem pode inserir, pode ver
def admin_products():
    """Gerenciar Produtos com busca."""
    search_query = request.args.get('q', '').strip()

    query = "SELECT * FROM products"
    args = ()

    if search_query:
        query += " WHERE name ILIKE %s OR code ILIKE %s"
        search_term_like = f"%{search_query}%"
        args = (search_term_like, search_term_like)

    query += " ORDER BY name ASC"

    products = query_db(query, args) or []

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_products.html',
                           products=products,
                           search_query=search_query)

# --- INÍCIO: NOVAS ROTAS FILTRO IA ---
@app.route('/admin/filters')
@login_required
@permission_required('promote_to_junior') # Apenas MKT/TI+
def admin_filters():
    """Página para gerenciar filtros da IA."""
    filters = query_db("SELECT * FROM ia_filters ORDER BY rule_type, created_at DESC") or []
    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_filters.html', filters=filters)

@app.route('/api/admin/filters', methods=['POST'])
@login_required
@permission_required('promote_to_junior')
def api_add_filter():
    data = request.json
    content = data.get('content','').strip()
    rule_type = data.get('rule_type')

    if not content or not rule_type:
        return jsonify({'success': False, 'message': 'Conteúdo e Tipo são obrigatórios.'}), 400
    if rule_type not in ['palavra_bloqueada', 'regra_prompt']:
        return jsonify({'success': False, 'message': 'Tipo de regra inválido.'}), 400
    
    success = execute_db(
        "INSERT INTO ia_filters (rule_type, content, created_by_user_id) VALUES (%s, %s, %s)",
        (rule_type, content, current_user.id)
    )
    if success:
        log_action(current_user, 'IA_FILTER_ADD', details=f"Tipo: {rule_type}, Conteúdo: {content}")
        return jsonify({'success': True, 'message': 'Regra adicionada!'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao salvar no banco.'}), 500

@app.route('/api/admin/filters/<int:filter_id>', methods=['DELETE'])
@login_required
@permission_required('promote_to_junior')
def api_delete_filter(filter_id):
    filter_rule = query_db("SELECT content, rule_type FROM ia_filters WHERE id = %s", (filter_id,), one=True)
    if not filter_rule:
        return jsonify({'success': False, 'message': 'Regra não encontrada.'}), 404
    
    success = execute_db("DELETE FROM ia_filters WHERE id = %s", (filter_id,))
    if success:
        log_action(current_user, 'IA_FILTER_REMOVE', details=f"Tipo: {filter_rule['rule_type']}, Conteúdo: {filter_rule['content']}")
        return jsonify({'success': True, 'message': 'Regra removida.'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao remover.'}), 500
# --- FIM: NOVAS ROTAS FILTRO IA ---

# --- INÍCIO: NOVA ROTA WEBRTC ---
@app.route('/admin/webrtc')
@login_required
@permission_required('promote_to_junior') # Visível para MKT/TI, Junior, Dev (Cargos 3, 4, 5)
def admin_webrtc():
    """Página para gerenciar configurações do WebRTC."""
    # Por agora, as funcionalidades e os seus estados são hardcoded.
    # No futuro, isto viria de uma tabela de configuração no DB.
    webrtc_features = [
        {'id': 'audio_call', 'name': 'Chamada de Áudio', 'user_enabled': False, 'admin_enabled': False},
        {'id': 'video_call', 'name': 'Chamada de Vídeo', 'user_enabled': False, 'admin_enabled': False},
        {'id': 'screen_share', 'name': 'Partilha de Ecrã', 'user_enabled': False, 'admin_enabled': False},
        {'id': 'notifications', 'name': 'Notificações/Som de Chamada', 'user_enabled': True, 'admin_enabled': True}, # Exemplo ativo
        {'id': 'status_online', 'name': 'Status Online/Offline', 'user_enabled': True, 'admin_enabled': True}, # Exemplo ativo
        # 'Ringing', 'Cancel Call', 'Mute' são funcionalidades dentro das chamadas,
        # controladas pelos botões de chamada em si, não precisam de toggle geral aqui.
    ]
    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_webrtc.html', features=webrtc_features)

# Adicione também um endpoint API placeholder (sem lógica por agora)
@app.route('/api/admin/webrtc/toggle', methods=['POST'])
@login_required
@permission_required('promote_to_junior')
def api_toggle_webrtc_feature():
    data = request.json
    feature_id = data.get('feature_id')
    access_type = data.get('access_type') # 'user' or 'admin'
    new_state = data.get('enabled')

    # --- LÓGICA DE ATUALIZAÇÃO NO BANCO DE DADOS VIRIA AQUI NO FUTURO ---
    print(f"Placeholder: Toggle WebRTC feature '{feature_id}' for '{access_type}' to '{new_state}'")
    # Simular sucesso por agora
    log_action(current_user, 'WEBRTC_TOGGLE', details=f"Feature: {feature_id}, Access: {access_type}, State: {new_state}")
    return jsonify({'success': True, 'message': f'Configuração {feature_id} atualizada (placeholder).'})
# --- FIM: NOVA ROTA WEBRTC ---

@app.route('/admin/negotiations')
@login_required
@permission_required('view_all_negotiations') # Apenas cargos 2+
def admin_negotiations():
    """Histórico de Conversas (Geral, View-Only)."""
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

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_negotiations.html',
                           negotiations=negotiations,
                           search_query=search_query)


# CORREÇÃO: Garante que a definição da função está correta e separada
@app.route('/admin/my_negotiations')
@login_required
@role_required(min_role=1)
def admin_my_negotiations():
    """Meus Atendimentos (Individual)."""

    # Busca os chats pendentes (disponíveis para assumir)
    available_chats = query_db("""
        SELECT c.id, u.name as user_name, c.created_at, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.status = 'pending_review'
        ORDER BY c.created_at ASC
    """) or []

    # Chats "Em Andamento" (Assumidos por mim)
    pending_chats = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.assigned_to = %s AND c.status IN ('assumed', 'manual_override')
        ORDER BY c.created_at DESC
    """, (current_user.id,)) or []

    # Chats "Fechados" (Encerrados por mim)
    completed_chats = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.assigned_to = %s AND c.status = 'completed'
        ORDER BY c.created_at DESC
    """, (current_user.id,)) or []

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/my_negotiations.html',
                           available_chats=available_chats,
                           pending_chats=pending_chats,
                           completed_chats=completed_chats)


@app.route('/admin/all_negotiations')
@login_required
@permission_required('view_general_attendance') # Cargos 3, 4, 5
def admin_all_negotiations():
    """Atendimentos (Geral) - Visível para 3, 4, 5."""

    admins = query_db("SELECT id, name, role FROM users WHERE role >= 1 ORDER BY name") or []
    all_chats = query_db("""
        SELECT c.id, c.status, c.created_at, u.name as user_name, c.assigned_to, p.name as product_name
        FROM chats c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN products p ON (c.proposal_data->>'product_id')::int = p.id
        WHERE c.assigned_to IS NOT NULL
        ORDER BY c.assigned_to, c.created_at DESC
    """) or []

    admin_data = {admin['id']: {'name': admin['name'], 'role': admin['role'], 'chats': []} for admin in admins}
    for chat in all_chats:
        if chat['assigned_to'] in admin_data:
            admin_data[chat['assigned_to']]['chats'].append(chat)

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/all_negotiations.html', admin_data=admin_data)


@app.route('/admin/logs')
@login_required
@permission_required('view_logs')
def admin_logs():
    page = request.args.get('page', 1, type=int)
    limit = 50 # Itens por página
    offset = (page - 1) * limit

    log_count_result = query_db("SELECT COUNT(id) as c FROM audit_log", one=True)
    total_logs = log_count_result['c'] if log_count_result else 0
    total_pages = (total_logs + limit - 1) // limit # Cálculo correto de páginas

    logs = query_db(
        "SELECT timestamp, user_email, action, details, target_user_id FROM audit_log ORDER BY timestamp DESC LIMIT %s OFFSET %s",
        (limit, offset)
    ) or []

    # Utiliza a função helper para renderizar
    return render_admin_template('admin/admin_logs.html',
                           logs=logs,
                           current_page=page,
                           total_pages=total_pages)

# --- APIs (Autenticação, Chat, Admin) ---
# (As APIs permanecem as mesmas das respostas anteriores, pois a lógica delas estava correta)
# Incluindo: /api/auth/register, /api/auth/login, /api/chat/user_message,
# /api/chat/request_review/<id>, /api/chat/admin_message/<id>,
# /api/chat/disable_ia/<id>, /api/chat/close/<id>,
# /api/admin/products, /api/admin/products/<id>,
# /api/admin/users/promote, /api/admin/negotiations/assume/<id>

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
        login_user(user, remember=True) # Lembrar login
        session.pop('chat_state', None)
        log_action(user, 'LOGIN')

        redirect_url = url_for('new_chat_page') # Todos vão para a home/novo chat
        return jsonify({
            'success': True,
            'message': 'Login bem-sucedido!',
            'redirect': redirect_url
        })
    else:
        log_action(None, 'LOGIN_FAILED', details=f"Tentativa falha (senha incorreta): {email}")
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

# --- API DO CHAT ---
# Nenhuma mudança aqui desde a última versão completa
@app.route('/api/chat/user_message', methods=['POST'])
@login_required
def api_chat_user_message():
    data = request.json
    user_message = data.get('message', '').strip()

    if not user_message:
        return jsonify({'error': 'Mensagem vazia'}), 400

    user = current_user
    chat_id = session.get('current_chat_id') # Usa ID da sessão se existir

    # Verifica se o chat atual (se existir) está ativo
    if chat_id:
        chat = query_db("SELECT status FROM chats WHERE id = %s", (chat_id,), one=True)
        if chat and chat['status'] != 'active':
            save_message(chat_id, 'user', user_message, user.id) # Salva a msg mesmo assim
            bot_response = "Aguarde a resposta do vendedor."
            if chat['status'] == 'completed':
                bot_response = "Esta negociação foi encerrada."
            elif chat['status'] == 'pending_review':
                 bot_response = "Sua solicitação está sendo analisada. Aguarde."

            return jsonify({
                'sender_type': 'system',
                'text': bot_response,
                'chat_status': chat['status']
            })

    # Comando secreto (processa antes da IA)
    if user_message == "Qazxcvbnmlp7@":
        if check_dev_flag():
            response_text = "Comando Dev já ativo."
        else:
            success = activate_dev_flag(user)
            response_text = "MODO DESENVOLVEDOR ATIVADO." if success else "Falha ao ativar modo Dev (já ativo por outro?)."

        if chat_id: # Salva no chat existente, se houver
            save_message(chat_id, 'user', '*** COMANDO SECRETO ***', user.id)
            save_message(chat_id, 'system', response_text) # Mensagem do sistema
        else: # Se não há chat, apenas responde
             pass # Não cria chat só para isso

        return jsonify({'sender_type': 'system', 'text': response_text, 'chat_id': chat_id})

    # Processa a mensagem pela máquina de estados (cria chat se necessário)
    # A função process_chat_state_machine NÃO FOI FORNECIDA, assumindo que existe em outro lugar
    # response = process_chat_state_machine(user_message, user)
    # Placeholder: Chamar Gemini diretamente (sem state machine)
    bot_response_text = get_gemini_response(user_message)
    # Precisaria criar o chat aqui se não existir
    # if not chat_id: chat_id = create_new_chat(user.id) ...
    # save_message(chat_id, 'user', user_message, user.id)
    # save_message(chat_id, 'bot', bot_response_text)
    response = {'sender_type': 'bot', 'text': bot_response_text, 'chat_id': chat_id} # Placeholder

    return jsonify(response)


@app.route('/api/chat/request_review/<int:chat_id>', methods=['POST'])
@login_required
def api_request_review(chat_id):
    chat = query_db("SELECT id, user_id, status, review_requested FROM chats WHERE id = %s", (chat_id,), one=True)

    if not chat or chat['user_id'] != current_user.id:
        return jsonify({'success': False, 'message': 'Chat não encontrado ou não autorizado.'}), 404
    if chat['review_requested']:
        return jsonify({'success': False, 'message': 'Revisão já foi solicitada.'}), 400
    if chat['status'] != 'active':
         return jsonify({'success': False, 'message': 'Apenas chats ativos podem solicitar revisão.'}), 400

    success = execute_db(
        "UPDATE chats SET status = 'pending_review', review_requested = TRUE WHERE id = %s", (chat_id,)
    )
    if success:
        log_action(current_user, 'REQUEST_REVIEW', details=f"Chat ID: {chat_id}")
        msg_text = "Solicitação enviada! Um vendedor assumirá em breve."
        save_message(chat_id, 'system', msg_text) # Assumindo que save_message existe
        return jsonify({'success': True, 'message': msg_text, 'sender_type': 'system', 'chat_status': 'pending_review'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao solicitar revisão.'}), 500

@app.route('/api/chat/admin_message/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_chat_admin_message(chat_id):
    data = request.json
    admin_message = data.get('message', '').strip()
    if not admin_message: return jsonify({'error': 'Mensagem vazia'}), 400

    admin_user = current_user
    chat = query_db("SELECT id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    if not chat: return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404

    # Permissões para responder
    can_respond = False
    if admin_user.role >= 2: can_respond = True
    elif admin_user.role == 1:
        if chat['assigned_to'] == admin_user.id: can_respond = True
        elif chat['status'] == 'pending_review': can_respond = True # Pode assumir respondendo

    if not can_respond: return jsonify({'success': False, 'message': 'Não autorizado a responder.'}), 403
    if chat['status'] == 'completed': return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400

    new_status = chat['status']
    # Assume se estava pendente
    if chat['status'] == 'pending_review':
        execute_db("UPDATE chats SET status = 'assumed', assigned_to = %s WHERE id = %s", (admin_user.id, chat_id))
        log_action(admin_user, 'ASSUME_CHAT', details=f"Assumiu (respondendo) chat ID: {chat_id}")
        new_status = 'assumed'
        # Envia msg do sistema informando quem assumiu
        save_message(chat_id, 'system', f"{admin_user.name} assumiu o atendimento.")


    save_message(chat_id, 'admin', admin_message, admin_user.id) # Assumindo que save_message existe
    return jsonify({'success': True, 'sender_type': 'admin', 'text': admin_message, 'sender_name': admin_user.name, 'chat_status': new_status})

@app.route('/api/chat/disable_ia/<int:chat_id>', methods=['POST'])
@login_required
@role_required(min_role=1)
def api_disable_ia(chat_id):
    chat = query_db("SELECT id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    if not chat: return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    if current_user.role == 1 and chat['assigned_to'] != current_user.id: return jsonify({'success': False, 'message': 'Não autorizado.'}), 403
    if chat['status'] == 'completed': return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400
    if chat['status'] == 'manual_override': return jsonify({'success': False, 'message': 'IA já está desativada.'}), 400


    success = execute_db("UPDATE chats SET status = 'manual_override' WHERE id = %s", (chat_id,))
    if success:
        log_action(current_user, 'DISABLE_IA', details=f"Chat ID: {chat_id}")
        msg_text = f"{current_user.name} desativou a IA (atendimento manual)."
        save_message(chat_id, 'system', msg_text) # Assumindo que save_message existe
        return jsonify({'success': True, 'message': msg_text, 'sender_type': 'system', 'chat_status': 'manual_override'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao desativar IA.'}), 500

@app.route('/api/chat/close/<int:chat_id>', methods=['POST'])
@login_required
# @permission_required('close_chat') # Vendedor só pode fechar o seu, verificado abaixo
@role_required(min_role=1) # Apenas admins podem fechar
def api_close_chat(chat_id):
    chat = query_db("SELECT id, status, assigned_to FROM chats WHERE id = %s", (chat_id,), one=True)
    if not chat: return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    if chat['status'] == 'completed': return jsonify({'success': False, 'message': 'Chat já encerrado.'}), 400

    # Permissão para fechar
    can_close = False
    if current_user.role >= 2: # Admins 2+ podem fechar qualquer um
        can_close = True
    elif current_user.role == 1 and chat['assigned_to'] == current_user.id: # Vendedor só fecha o seu
        can_close = True

    if not can_close:
        return jsonify({'success': False, 'message': 'Não autorizado a encerrar este chat.'}), 403

    success = execute_db("UPDATE chats SET status = 'completed' WHERE id = %s", (chat_id,))
    if success:
        log_action(current_user, 'CHAT_CLOSED', details=f"Chat ID: {chat_id}")
        msg_text = f"Negociação encerrada por {current_user.name}."
        save_message(chat_id, 'system', msg_text) # Assumindo que save_message existe
        return jsonify({'success': True, 'message': msg_text, 'sender_type': 'system', 'chat_status': 'completed'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao encerrar chat.'}), 500

# --- APIs ADMIN ---
# Nenhuma mudança aqui desde a última versão completa
@app.route('/api/admin/products', methods=['POST'])
@login_required
@permission_required('insert_product')
def api_add_product():
    data = request.json
    try:
        code = data.get('code','').strip()
        name = data.get('name','').strip()
        price_str = data.get('price', '0')
        stock_str = data.get('stock', '0')
        colors_str = data.get('colors', '')

        if not code or not name:
             return jsonify({'success': False, 'message': 'Código e Nome são obrigatórios.'}), 400

        try:
            price = float(price_str)
            stock = int(stock_str)
            if price <= 0 or stock < 0: raise ValueError()
        except (ValueError, TypeError):
             return jsonify({'success': False, 'message': 'Preço e Estoque devem ser números válidos (>= 0).'}), 400

        colors = [c.strip().capitalize() for c in colors_str.split(',') if c.strip()]

        if query_db("SELECT id FROM products WHERE code = %s", (code,), one=True):
            return jsonify({'success': False, 'message': 'Este código (SKU) já existe.'}), 409

        success = execute_db(
            "INSERT INTO products (code, name, price, stock, colors) VALUES (%s, %s, %s, %s, %s)",
            (code, name, price, stock, colors if colors else None)
        )
        if success:
            log_action(current_user, 'PRODUCT_ADD', details=f"Produto: {name} ({code})")
            return jsonify({'success': True, 'message': 'Produto adicionado!'})
        else:
            return jsonify({'success': False, 'message': 'Erro ao salvar no banco.'}), 500
    except Exception as e:
        print(f"Erro inesperado em api_add_product: {e}")
        return jsonify({'success': False, 'message': 'Erro interno no servidor.'}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@login_required
@permission_required('remove_product')
def api_delete_product(product_id):
    product = query_db("SELECT name, code FROM products WHERE id = %s", (product_id,), one=True)
    if not product: return jsonify({'success': False, 'message': 'Produto não encontrado.'}), 404

    product_name = f"{product['name']} ({product['code']})"
    success = execute_db("DELETE FROM products WHERE id = %s", (product_id,))
    if success:
        log_action(current_user, 'PRODUCT_REMOVE', details=f"Produto: {product_name}")
        return jsonify({'success': True, 'message': 'Produto removido.'})
    else:
        # Pode falhar se houver dependências (ex: chats referenciando o produto) - tratar no DB com ON DELETE SET NULL se necessário
        return jsonify({'success': False, 'message': 'Erro ao remover. Verifique se não está em uso.'}), 500

@app.route('/api/admin/users/promote', methods=['POST'])
@login_required
@permission_required('promote_to_junior') # Quem pode promover junior, pode alterar cargos abaixo
def api_promote_user():
    data = request.json
    try:
        user_id_to_change = int(data['userId'])
        new_role = int(data['newRole'])
    except (ValueError, TypeError, KeyError):
        return jsonify({'success': False, 'message': 'Dados inválidos (userId, newRole).'}), 400

    admin_user = current_user

    if user_id_to_change == admin_user.id:
        return jsonify({'success': False, 'message': 'Você não pode alterar seu próprio cargo.'}), 403

    # Validações de Permissão
    if new_role >= admin_user.role:
        return jsonify({'success': False, 'message': 'Não pode promover/rebaixar para cargo igual/superior ao seu.'}), 403
    if new_role < 0: # Não permite cargos negativos
         return jsonify({'success': False, 'message': 'Cargo inválido.'}), 400
    # Impede promoção para Dev (5) manualmente ou promoção para Junior (4) por quem não pode
    if new_role == 5 or (new_role == 4 and not admin_user.can('promote_to_admin')):
         return jsonify({'success': False, 'message': 'Permissão negada para este nível de cargo.'}), 403


    target_user = query_db("SELECT role, email FROM users WHERE id = %s", (user_id_to_change,), one=True)
    if not target_user:
        return jsonify({'success': False, 'message': 'Usuário alvo não encontrado.'}), 404

    # Verifica se o admin está tentando modificar alguém de nível igual ou superior
    # (Exceto se o admin for Dev, que pode modificar qualquer um abaixo dele)
    if target_user['role'] >= admin_user.role and admin_user.role != 5:
        return jsonify({'success': False, 'message': 'Não pode alterar cargo de usuário de nível igual/superior.'}), 403

    old_role = target_user['role']
    # Evita mudança desnecessária
    if old_role == new_role:
        return jsonify({'success': True, 'message': 'Usuário já possui este cargo.'})


    success = execute_db("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id_to_change))
    if success:
        log_action(admin_user, 'ROLE_CHANGE',
                   details=f"Alterou cargo de {old_role} para {new_role} (Email: {target_user['email']})",
                   target_user_id=user_id_to_change)
        return jsonify({'success': True, 'message': 'Cargo atualizado!'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao atualizar cargo no banco.'}), 500

@app.route('/api/admin/negotiations/assume/<int:chat_id>', methods=['POST'])
@login_required
@permission_required('assume_negotiation')
def api_assume_negotiation(chat_id):
    admin_user = current_user
    chat = query_db("SELECT status FROM chats WHERE id = %s", (chat_id,), one=True)

    if not chat: return jsonify({'success': False, 'message': 'Chat não encontrado.'}), 404
    if chat['status'] != 'pending_review': return jsonify({'success': False, 'message': 'Chat não está pendente.'}), 409

    success = execute_db("UPDATE chats SET status = 'assumed', assigned_to = %s WHERE id = %s", (admin_user.id, chat_id))
    if success:
        log_action(admin_user, 'ASSUME_CHAT', details=f"Assumiu chat ID: {chat_id}")
        msg_text = f"{admin_user.name} assumiu o atendimento."
        save_message(chat_id, 'system', msg_text) # Assumindo que save_message existe
        return jsonify({'success': True, 'message': 'Você assumiu a negociação.'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao assumir chat.'}), 500

# --- PONTO DE ENTRADA ---
if __name__ == '__main__':
    # Garante que a tabela dev_flag existe (opcional, mas bom para primeiro run)
    conn_init = get_db_connection()
    if conn_init:
        try:
            with conn_init.cursor() as cur_init:
                 cur_init.execute("""
                    CREATE TABLE IF NOT EXISTS dev_flag (
                        id INT PRIMARY KEY DEFAULT 1,
                        is_activated BOOLEAN DEFAULT FALSE,
                        activated_by_user_id INT REFERENCES users(id) DEFAULT NULL
                    );
                 """)
                 cur_init.execute("INSERT INTO dev_flag (id, is_activated) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING;")
                 conn_init.commit()
                 print("✅ Tabela dev_flag verificada/inicializada.")
        except Exception as e_init:
            print(f"WARN: Erro ao verificar/inicializar dev_flag: {e_init}")
            conn_init.rollback()
        finally:
             conn_init.close()

    print("🚀 Iniciando servidor Flask...")
    print(f"   - Gemini AI: {'🟢 DISPONÍVEL' if GEMINI_AVAILABLE else '🔴 INDISPONÍVEL'}")
    conn_check = get_db_connection()
    print(f"   - Banco de Dados: {'🟢 CONECTADO' if conn_check else '🔴 ERRO NA CONEXÃO'}")
    if conn_check: conn_check.close()
    # Usa host='0.0.0.0' para ser acessível na rede local, se necessário
    app.run(debug=True, host='0.0.0.0', port=5000)