from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import re
import magic

# Importar utilitários personalizados
try:
    from config import config
    from utils.logging_config import setup_logging, log_user_action, log_security_event, log_error
    from utils.security import (
        sanitize_input, validate_file_upload, secure_file_save, 
        validate_password_strength, rate_limit, validate_email
    )
    from utils.pagination import paginate_query, get_pagination_info
except ImportError as e:
    print(f"Aviso: Não foi possível importar utilitários: {e}")
    # Definir funções dummy para compatibilidade
    def sanitize_input(text): return text
    def log_user_action(*args): pass
    def log_security_event(*args): pass
    def log_error(*args): pass

#https://sites.google.com/site/bradockrpg/vampiro-a-mascara-estruturas-vampiricas0
app = Flask(__name__)

# Configurar aplicação
try:
    config_name = os.environ.get('FLASK_CONFIG') or 'default'
    app.config.from_object(config[config_name])
except:
    # Fallback para configuração básica
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lilith.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Configurar logging
try:
    setup_logging(app)
except:
    pass

# Inicializa o SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Nome da rota de login

# Inicializa o LoginManager
login_manager.login_message = "Por favor, faça login para acessar essa página."
login_manager.login_message_category = "info"

# Modelo de usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_master = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)  # Token para recuperação de senha
    user_image = db.Column(db.String(255), nullable=True)  # Caminho da imagem do usuário
    
    # Configurações de notificação
    adventure_notifications = db.Column(db.Boolean, default=True)
    character_notifications = db.Column(db.Boolean, default=True)
    system_notifications = db.Column(db.Boolean, default=True)
    

    def set_password(self, password):
        """Hasheia a senha e a salva"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha inserida corresponde ao hash armazenado"""
        return check_password_hash(self.password, password)

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user
    return None

# Função para validar a senha (melhorada)
def is_password_valid(password):
    """
    Verifica se a senha atende aos critérios de segurança
    """
    try:
        is_valid, message = validate_password_strength(password)
        return is_valid
    except:
        # Fallback para validação básica
        pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%!&*]).{8,}$'
        return re.match(pattern, password) is not None

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Rota de login com rate limiting
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Se o usuário já está autenticado, redirecione para a dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Se o método é POST, tentamos realizar o login
    if request.method == 'POST':
        try:
            # Rate limiting para tentativas de login
            from datetime import datetime, timedelta
            client_ip = request.remote_addr
            
            # Verificar rate limiting manual (fallback)
            session_key = f'login_attempts_{client_ip}'
            attempts = session.get(session_key, [])
            now = datetime.now()
            
            # Limpar tentativas antigas (últimos 15 minutos)
            attempts = [attempt for attempt in attempts if now - datetime.fromisoformat(attempt) < timedelta(minutes=15)]
            
            if len(attempts) >= 5:
                log_security_event('RATE_LIMIT_EXCEEDED', f'IP: {client_ip}', None)
                flash('Muitas tentativas de login. Tente novamente em 15 minutos.', 'error')
                return render_template('login.html')
            
            user = sanitize_input(request.form['user'])
            password = request.form['password']
        
            # Busca o usuário pelo nome de usuário
            user_obj = User.query.filter_by(user=user).first()

            # Verifica se o usuário existe e se a senha está correta
            if user_obj and check_password_hash(user_obj.password, password):
                login_user(user_obj)
                
                # Limpar tentativas de login da sessão
                session.pop(session_key, None)
                
                # Log de login bem-sucedido
                log_user_action(user_obj.id, 'LOGIN_SUCCESS', f'IP: {client_ip}')
                
                flash('Login bem-sucedido!', 'success')

                # Redireciona para a página pretendida ou dashboard
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                # Registrar tentativa falhada
                attempts.append(now.isoformat())
                session[session_key] = attempts
                
                # Log de tentativa de login falhada
                log_security_event('LOGIN_FAILED', f'User: {user}, IP: {client_ip}', None)
                
                flash('Nome de usuário ou senha incorretos.', 'danger')
                
        except Exception as e:
            log_error('LOGIN_ERROR', str(e), None)
            flash('Erro interno. Tente novamente.', 'error')

    return render_template('signin.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email não encontrado.', 'danger')
            return redirect(url_for('forgot_password'))

        # Gerar token de recuperação
        token = s.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)
        flash(f'Use o link para redefinir sua senha: {reset_url}', 'info')
        # Aqui, você pode enviar um e-mail com `reset_url`.

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Expira em 1 hora
    except BadSignature:
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        if len(password) < 8:
            flash('Senha deve ter no mínimo 8 caracteres.', 'danger')
            return redirect(url_for('reset_password', token=token))

        hashed_password = generate_password_hash(password)
        user = User.query.filter_by(email=email).first()
        user.password = hashed_password
        db.session.commit()

        flash('Senha redefinida com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Rota para dashboard (requer login)
@app.route('/dashboard')
@login_required
def dashboard():
    # Get data that might be useful for the dashboard
    adventures = Adventure.query.all()
    characters = ImportantCharacter.query.filter_by(visible=True).all()
    user_adventures = Adventure.query.filter_by(creator_id=current_user.id).all()
    
    # Pass more context data to the template for a richer dashboard
    return render_template('dashboard.html', 
                          user=current_user.user if current_user.is_authenticated else None,
                          adventures=adventures,
                          characters=characters,
                          user_adventures=user_adventures)
    

@app.route('/player_dashboard')
@login_required
def player_dashboard():
    # Obter personagens criados pelo usuário
    user_characters = ImportantCharacter.query.filter_by(created_by=current_user.id).all()
    # Obter aventuras criadas pelo usuário
    user_adventures = Adventure.query.filter_by(creator_id=current_user.id).all()
    return render_template('player_dashboard.html', user_characters=user_characters, user_adventures=user_adventures)
    

@app.route('/dashboard2')
@login_required
def dashboard2():
    return render_template('dashboard2.html',  user=current_user.user if current_user.is_authenticated else None)

@app.route('/admin_logins')
@login_required  # Somente usuários logados podem acessar
def admin_logins():
    if not current_user.is_admin:
        abort(403)  # Apenas admins podem acessar
    users = User.query.all()
    return render_template('admin_logins.html', users=users)

@app.route('/admin_clans')
@login_required
def admin_clans():
    # Verificar se o usuário é admin ou mestre
    if not (current_user.is_admin or current_user.is_master):
        abort(403)  # Acesso negado
    # Aqui você pode adicionar a lógica para gerenciar clans
    # Por enquanto, vamos apenas renderizar um template básico
    return render_template('admin_clans.html')

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        abort(403)
    
    user = request.form.get('user')
    email = request.form.get('email')
    password = request.form.get('password')

    # Verificar se o usuário já existe
    if User.query.filter_by(email=email).first():
        flash('Email já registrado', 'danger')
        return redirect(url_for('admin_logins'))

    new_user = User(
        user=user,
        email=email,
        password=generate_password_hash(password)
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    flash('Usuário adicionado com sucesso', 'success')
    return redirect(url_for('admin_logins'))


@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.user = request.form.get('user')
    user.email = request.form.get('email')

    password = request.form.get('password')
    if password:
        user.password = generate_password_hash(password)

    db.session.commit()
    flash('Usuário atualizado com sucesso', 'success')
    return redirect(url_for('admin_logins'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash('Usuário excluído com sucesso', 'success')
    return redirect(url_for('admin_logins'))

@app.route('/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()

    flash(f'Usuário {user.user} agora é administrador!', 'success')
    return redirect(url_for('admin_logins'))

@app.route('/make_master/<int:user_id>', methods=['POST'])
@login_required
def make_master(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_master = True
    db.session.commit()

    flash(f'Usuário {user.user} agora é mestre!', 'success')
    return redirect(url_for('admin_logins'))

@app.route('/remove_master/<int:user_id>', methods=['POST'])
@login_required
def remove_master(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_master = False
    db.session.commit()

    flash(f'Usuário {user.user} não é mais mestre!', 'success')
    return redirect(url_for('admin_logins'))

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu com sucesso.', 'info')
    return redirect(url_for('login'))

# Rota para atualizar perfil do usuário
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user
    user.user = request.form.get('username')
    user.email = request.form.get('email')
    
    # Verificar se uma nova imagem foi enviada
    if 'profile_image' in request.files:
        image_file = request.files['profile_image']
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            user.user_image = f'uploads/{image_filename}'
    
    db.session.commit()
    flash('Perfil atualizado com sucesso!', 'success')
    return redirect(url_for('player_dashboard'))

# Rota para atualizar configurações de notificação
@app.route('/update_notification_settings', methods=['POST'])
@login_required
def update_notification_settings():
    user = current_user
    
    # Atualizar configurações de notificação
    user.adventure_notifications = 'adventure_notifications' in request.form
    user.character_notifications = 'character_notifications' in request.form
    user.system_notifications = 'system_notifications' in request.form
    
    db.session.commit()
    flash('Configurações de notificação atualizadas com sucesso!', 'success')
    return redirect(url_for('player_dashboard'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # Verificar se o usuário digitou "EXCLUIR" para confirmar
    confirm_text = request.form.get('confirm_delete')
    password = request.form.get('password')
    
    if confirm_text != "EXCLUIR":
        flash('Por favor, digite "EXCLUIR" para confirmar a exclusão da conta.', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Verificar a senha do usuário
    if not check_password_hash(current_user.password, password):
        flash('Senha incorreta. Por favor, tente novamente.', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Buscar todos os personagens do usuário para excluir
    user_characters = Character.query.filter_by(user_id=current_user.id).all()
    for character in user_characters:
        db.session.delete(character)
    
    # Buscar todas as aventuras do usuário para excluir
    user_adventures = Adventure.query.filter_by(created_by=current_user.id).all()
    for adventure in user_adventures:
        db.session.delete(adventure)
    
    # Excluir o usuário
    user = User.query.get(current_user.id)
    
    # Fazer logout antes de excluir
    logout_user()
    
    # Excluir o usuário do banco de dados
    db.session.delete(user)
    db.session.commit()
    
    flash('Sua conta foi excluída permanentemente.', 'success')
    return redirect(url_for('index'))

# Rota para alterar senha do usuário logado
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Verificar se a senha atual está correta
    if not check_password_hash(current_user.password, current_password):
        flash('Senha atual incorreta.', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Verificar se a nova senha e a confirmação coincidem
    if new_password != confirm_password:
        flash('As senhas não coincidem.', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Validação de senha
    if not is_password_valid(new_password):
        flash(
            "A senha deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma minúscula, um número e um caractere especial (@, #, $, %).",
            "danger"
        )
        return redirect(url_for('player_dashboard'))
    
    # Atualizar a senha
    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    
    flash('Senha alterada com sucesso!', 'success')
    return redirect(url_for('player_dashboard'))

# Rota de registro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Sanitizar entradas
            user = sanitize_input(request.form['user'].strip())
            password = request.form['password']
            email = sanitize_input(request.form['email'].strip().lower())
            
            # Validações básicas
            if not user or not password or not email:
                flash('Todos os campos são obrigatórios.', 'danger')
                return redirect(url_for('register'))
            
            # Validar formato do email
            try:
                if not validate_email(email):
                    flash('Formato de email inválido.', 'danger')
                    return redirect(url_for('register'))
            except:
                # Fallback para validação básica
                if '@' not in email or '.' not in email:
                    flash('Formato de email inválido.', 'danger')
                    return redirect(url_for('register'))
            
            # Validar nome de usuário
            if len(user) < 3 or len(user) > 50:
                flash('Nome de usuário deve ter entre 3 e 50 caracteres.', 'danger')
                return redirect(url_for('register'))
            
            # Validação de senha melhorada
            try:
                is_valid, message = validate_password_strength(password)
                if not is_valid:
                    flash(message, 'danger')
                    return redirect(url_for('register'))
            except:
                # Fallback para validação básica
                if not is_password_valid(password):
                    flash(
                        "A senha deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma minúscula, um número e um caractere especial.",
                        "danger"
                    )
                    return redirect(url_for('register'))

            # Verificar se o e-mail já está registrado
            if User.query.filter_by(email=email).first():
                log_security_event('DUPLICATE_EMAIL_REGISTRATION', f'Email: {email}', None)
                flash("E-mail já registrado. Tente novamente com outro e-mail.", "warning")
                return redirect(url_for('register'))

            # Verificar se o usuário já está registrado
            if User.query.filter_by(user=user).first():
                log_security_event('DUPLICATE_USER_REGISTRATION', f'User: {user}', None)
                flash("Nome de usuário já registrado. Tente novamente com outro nome.", "warning")
                return redirect(url_for('register'))

            # Cria um novo usuário e hashea a senha
            new_user = User(user=user, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            # Log de registro bem-sucedido
            log_user_action(new_user.id, 'USER_REGISTERED', f'Email: {email}')

            flash('Registro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            log_error('REGISTRATION_ERROR', str(e), None)
            flash('Erro interno durante o registro. Tente novamente.', 'error')
            return redirect(url_for('register'))

    return render_template('signup.html')

class Adventure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    requester = db.Column(db.String(100), nullable=False)
    reward = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    document = db.Column(db.String(255), nullable=True)  # Caminho do documento anexado
    image = db.Column(db.String(255), nullable=True)     # Caminho da imagem anexada
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Criador da aventura
    responsible_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Usuário responsável pela aventura
    status = db.Column(db.String(100), nullable=False, default='Disponivel')
    finished = db.Column(db.String(500), nullable=True)  # aventura finalizada

    creator = db.relationship('User', foreign_keys=[creator_id])
    responsible_user = db.relationship('User', foreign_keys=[responsible_user_id])

    def __repr__(self):
        return f"<Adventure {self.title}>"

    
    # Configuração para o upload
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'mp3', 'wav', 'ogg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Função para verificar extensão de arquivo
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_secure(file):
    """Função de validação de arquivo (mantida para compatibilidade)"""
    try:
        return validate_file_upload(file)
    except:
        # Fallback para validação básica
        if not file or not file.filename:
            return False, "Nenhum arquivo selecionado"
        
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'mp3', 'wav', 'ogg'}
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in allowed_extensions:
            return False, f"Extensão {ext} não permitida"
        
        # Verificar tamanho (16MB max)
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > 16 * 1024 * 1024:
            return False, "Arquivo muito grande (máximo 16MB)"
        
        return True, "Arquivo aceito"

@app.route('/create_adventure', methods=['GET', 'POST'])
@login_required
def create_adventure():
    if request.method == 'POST':
        try:
            # Sanitizar entradas
            title = sanitize_input(request.form['title'].strip())
            requester = sanitize_input(request.form['requester'].strip())
            reward = sanitize_input(request.form['reward'].strip())
            description = sanitize_input(request.form['description'].strip())
            
            # Validações básicas
            if not title or not requester or not reward or not description:
                flash('Todos os campos obrigatórios devem ser preenchidos.', 'danger')
                return redirect(url_for('create_adventure'))
            
            if len(title) > 200 or len(requester) > 100 or len(reward) > 100:
                flash('Alguns campos excedem o tamanho máximo permitido.', 'danger')
                return redirect(url_for('create_adventure'))
            
            document = None
            image = None

            # Processamento seguro de arquivos
            if 'document' in request.files:
                document_file = request.files['document']
                if document_file and document_file.filename:
                    try:
                        document = secure_file_save(document_file, app.config['UPLOAD_FOLDER'], 'documents')
                    except ValueError as e:
                        flash(f'Erro no documento: {str(e)}', 'danger')
                        return redirect(url_for('create_adventure'))
                    except Exception as e:
                        log_error('FILE_UPLOAD_ERROR', f'Document upload failed: {str(e)}', current_user.id)
                        flash('Erro ao fazer upload do documento.', 'danger')
                        return redirect(url_for('create_adventure'))

            if 'image' in request.files:
                image_file = request.files['image']
                if image_file and image_file.filename:
                    try:
                        image = secure_file_save(image_file, app.config['UPLOAD_FOLDER'], 'images')
                    except ValueError as e:
                        flash(f'Erro na imagem: {str(e)}', 'danger')
                        return redirect(url_for('create_adventure'))
                    except Exception as e:
                        log_error('FILE_UPLOAD_ERROR', f'Image upload failed: {str(e)}', current_user.id)
                        flash('Erro ao fazer upload da imagem.', 'danger')
                        return redirect(url_for('create_adventure'))

            # Criar nova aventura e salvar no banco de dados
            new_adventure = Adventure(
                title=title,
                requester=requester,
                reward=reward,
                description=description,
                document=document,
                image=image,
                creator_id=current_user.id
            )
            db.session.add(new_adventure)
            db.session.commit()
            
            # Log da criação da aventura
            log_user_action(current_user.id, 'ADVENTURE_CREATED', f'Title: {title}')

            flash('Aventura criada com sucesso!', 'success')
            return redirect(url_for('campaigns'))
            
        except Exception as e:
            db.session.rollback()
            log_error('ADVENTURE_CREATION_ERROR', str(e), current_user.id)
            flash('Erro interno ao criar aventura. Tente novamente.', 'error')
            return redirect(url_for('create_adventure'))

    return render_template('create_adventure.html')

@app.route('/adventure/<int:adventure_id>')
@login_required
def adventure_detail(adventure_id):
    adventure = Adventure.query.get_or_404(adventure_id)
    return render_template('adventure_detail.html', adventure=adventure)

# Rota para exibir aventuras por status
@app.route('/adventures/<string:status>')
@login_required
def show_adventures(status):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Número de aventuras por página
        
        # Query base
        query = Adventure.query.filter_by(status=status)
        
        # Aplicar paginação
        try:
            pagination = paginate_query(query, page, per_page)
            adventures = pagination.items
            pagination_info = get_pagination_info(page, per_page, pagination.total_count)
        except:
            # Fallback sem paginação
            adventures = query.all()
            pagination_info = None
            
        return render_template('show_adventures.html', 
                             adventures=adventures, 
                             status=status,
                             pagination=pagination_info)
                             
    except Exception as e:
        log_error('SHOW_ADVENTURES_ERROR', str(e), current_user.id if current_user.is_authenticated else None)
        flash('Erro ao carregar aventuras.', 'error')
        return redirect(url_for('index'))

@app.route('/start_adventure', methods=['POST'])
@login_required
def start_adventure():
    # Obter o ID da aventura do formulário
    adventure_id = request.form.get('adventure_id')

    if not adventure_id:
        flash("Por favor, selecione uma aventura para iniciar.", "warning")
        return redirect(url_for('sala_do_mestre'))

    # Buscar a aventura selecionada
    try:
        adventure_id = int(adventure_id)
        adventure = Adventure.query.get_or_404(adventure_id)
    except ValueError:
        flash("ID de aventura inválido.", "danger")
        return redirect(url_for('sala_do_mestre'))

    # Definir o usuário atual como responsável pela aventura
    adventure.responsible_user_id = current_user.id
    adventure.status = "Em andamento"
    db.session.commit()

    flash('Você é agora o responsável por essa aventura!', 'success')
    return redirect(url_for('adventure_detail', adventure_id=adventure.id))


@app.route('/edit_adventure/<int:adventure_id>', methods=['GET', 'POST'])
@login_required
def edit_adventure(adventure_id):
    adventure = Adventure.query.get_or_404(adventure_id)

    # Verificar se o usuário atual é o criador ou um admin
    if not (current_user.is_admin or adventure.creator_id == current_user.id):
        abort(403)  # Se não for admin ou criador, proíbe o acesso

    if request.method == 'POST':
        # Atualiza os dados da aventura com os dados enviados no formulário
        adventure.title = request.form['title']
        adventure.requester = request.form['requester']
        adventure.reward = request.form['reward']
        adventure.description = request.form['description']
        adventure.finished = request.form['finished']

        # Atualiza o arquivo de documento, se enviado
        if 'document' in request.files:
            document_file = request.files['document']
            if document_file and allowed_file(document_file.filename):
                document_filename = secure_filename(document_file.filename)
                document_file.save(os.path.join(app.config['UPLOAD_FOLDER'], document_filename))
                adventure.document = f'uploads/{document_filename}'

        # Atualiza o arquivo de imagem, se enviado
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                adventure.image = f'uploads/{image_filename}'

        db.session.commit()
        flash('Aventura atualizada com sucesso!', 'success')
        return redirect(url_for('adventure_detail', adventure_id=adventure.id))

    return render_template('edit_adventure.html', adventure=adventure)


@app.route('/delete_adventure/<int:adventure_id>', methods=['POST'])
@login_required
def delete_adventure(adventure_id):
    adventure = Adventure.query.get_or_404(adventure_id)

    # Verificar se o usuário atual é o criador ou um admin
    if not (current_user.is_admin or adventure.creator_id == current_user.id):
        abort(403)

    db.session.delete(adventure)
    db.session.commit()
    flash('Aventura apagada com sucesso!', 'success')
    return redirect(url_for('campaigns'))

class ImportantCharacter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    race = db.Column(db.String(50), nullable=False)  # Ex: 'vampire', 'human', 'demon', etc.
    clan = db.Column(db.String(100), nullable=False)
    bloodline = db.Column(db.String)
    personalidade = db.Column(db.Text)
    poderes_habilidades = db.Column(db.Text)
    conexoes = db.Column(db.Text)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Caminho da imagem
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Criador do personagem
    visible = db.Column(db.Boolean, default=False, nullable=False)  # Visível para todos


@app.route('/set_visible/<int:important_character_id>', methods=['POST'])
@login_required
def set_visible(important_character_id):
    important_character = ImportantCharacter.query.get_or_404(important_character_id)
    if not current_user.is_admin:
        abort(403)

    # Definir o valor do campo visible para 1
    important_character.visible = not important_character.visible
    db.session.commit()
    flash('Visibilidade do personagem alterada para visível!', 'success')

    return redirect(url_for('admin_characters'))

@app.route('/toggle_visibility/<int:character_id>', methods=['POST'])
@login_required
def toggle_visibility(character_id):
    character = ImportantCharacter.query.get_or_404(character_id)

    # Log para depuração
    print(f"Toggling visibility for character {character.id}, current visibility: {character.visible}")

    try:
        # Alternar o valor do campo visible
        character.visible = not character.visible
        db.session.commit()
        flash('Visibilidade do personagem alterada com sucesso!', 'success')
    except Exception as e:
        print(f"Erro ao alterar visibilidade: {e}")
        flash('Erro ao alterar a visibilidade do personagem.', 'danger')

    # Redirecionar para a página de administração
    return redirect(url_for('admin_characters'))


@app.route('/admin_characters')
@login_required
def admin_characters():
    important_characters = ImportantCharacter.query.order_by(ImportantCharacter.id.desc()).all()
    return render_template('admin_characters.html', important_characters=important_characters)

@app.route('/update_importantcharacters', methods=['POST'])
@login_required
def update_importantcharacters():
    important_characters = ImportantCharacter.query.all()

    # Percorre todos os personagens importantes e atualiza seus valores com os dados enviados do formulário
    for important_character in important_characters:
        important_character.name = request.form.get(f'name_{important_character.id}')
        important_character.race = request.form.get(f'race_{important_character.id}')
        important_character.bloodline = request.form.get(f'bloodline_{important_character.id}')
        important_character.clan = request.form.get(f'clan_{important_character.id}')
        important_character.description = request.form.get(f'description_{important_character.id}')
        important_character.visible = bool(request.form.get(f'visible_{important_character.id}'))

    db.session.commit()  # Salva as mudanças no banco de dados
    flash('Personagens importantes atualizados com sucesso!', 'success')
    return redirect(url_for('admin_characters'))



@app.route('/delete_importantcharacter/<int:id>', methods=['POST'])
@login_required
def delete_importantcharacter(id):
    import_character = ImportantCharacter.query.get_or_404(id)

    db.session.delete(import_character)
    db.session.commit()

    flash('Personagem deletado com sucesso.', 'success')
    return redirect(url_for('admin_characters'))

@app.route('/create_character', methods=['GET', 'POST'])
@login_required
def create_character():
    if request.method == 'POST':
        name = request.form['name']
        race = request.form['race']
        clan = request.form['clan']
        bloodline = request.form['bloodline']
        description = request.form['description']

        # Processamento de imagem
        image = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                image = f'uploads/{image_filename}'

        # Criar novo personagem importante
        new_character = ImportantCharacter(
            name=name,
            race=race,
            clan=clan,
            bloodline=bloodline,
            description=description,
            personalidade=request.form.get('personalidade'),
            poderes_habilidades=request.form.get('poderes_habilidades'),
            conexoes=request.form.get('conexoes'),
            image=image,
            created_by=current_user.id
        )

        db.session.add(new_character)
        db.session.commit()
        flash('Personagem criado com sucesso!', 'success')
        return redirect(url_for('admin_characters', race=race))

    return render_template('create_character.html')

@app.route('/characters/<string:race>')
def show_characters_by_race(race):
    # Filtrar personagens importantes pela raça
    characters = ImportantCharacter.query.filter_by(race=race).all()
    return render_template('show_characters_by_race.html', characters=characters, race=race)


@app.route('/edit_character/<int:character_id>', methods=['GET', 'POST'])
@login_required
def edit_character(character_id):
    character = ImportantCharacter.query.get_or_404(character_id)

    # Verificar se o usuário é o criador ou um admin
    if not (current_user.is_admin or character.created_by == current_user.id):
        abort(403)  # Proibir acesso se não for permitido

    if request.method == 'POST':
        # Atualizar detalhes do personagem
        character.name = request.form['name']
        character.race = request.form['race']
        character.description = request.form['description']
        if current_user.is_master:
            character.personalidade = request.form.get('personalidade', '')
            character.poderes_habilidades = request.form.get('poderes_habilidades', '')
            character.conexoes = request.form.get('conexoes', '')


        # Atualizar imagem se uma nova foi enviada
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                character.image = f'uploads/{image_filename}'

        db.session.commit()
        flash('Personagem atualizado com sucesso!', 'success')
        return redirect(url_for('character_detail', character_id=character.id))

    return render_template('edit_character.html', character=character)

# Definição correta para delete_character
@app.route('/delete_character/<int:character_id>', methods=['POST'])
@login_required
def delete_character(character_id):
    character = ImportantCharacter.query.get_or_404(character_id)

    # Verificar se o usuário é o criador ou um admin
    if not (current_user.is_admin or character.created_by == current_user.id):
        abort(403)

    db.session.delete(character)
    db.session.commit()
    flash('Personagem deletado com sucesso!', 'success')
    return redirect(url_for('show_characters_by_race', race=character.race))

# Certifique-se de que character_detail não esteja duplicado
@app.route('/character_detail/<int:character_id>')
def character_detail(character_id):
    character = ImportantCharacter.query.get_or_404(character_id)
    return render_template('character_detail.html', character=character)

# Modelo para campos editaveis
class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(000), nullable=False)


# Modelo para personagem
class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    race = db.Column(db.String(50), nullable=False)
    mask = db.Column(db.String(100))
    clan = db.Column(db.String(50))
    level = db.Column(db.Integer)
    bloodline = db.Column(db.String(100))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamento
    creator = db.relationship('User', backref='characters')

    def __repr__(self):
        return f'<Character {self.name}>'



# Exibir personagens na página
@app.route('/show_characters')
@login_required
def show_characters():
    characters = Character.query.all()
    return render_template('show_characters.html', characters=characters)

@app.route('/update_characters', methods=['POST'])
@login_required
def update_characters():
    characters = Character.query.all()

    # Percorre todos os personagens e atualiza seus valores com os dados enviados do formulário
    for character in characters:
        character.name = request.form.get(f'name_{character.id}')
        character.mask = request.form.get(f'mask_{character.id}')
        character.clan = request.form.get(f'clan_{character.id}')
        character.level = request.form.get(f'level_{character.id}')
        character.bloodline = request.form.get(f'bloodline_{character.id}')
        character.description = request.form.get(f'description_{character.id}')

    db.session.commit()  # Salva as mudanças no banco de dados
    flash('Personagens atualizados com sucesso!', 'success')
    return redirect(url_for('show_characters'))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/characters')
def characters():
    characters = ImportantCharacter.query.all()
    return render_template('characters.html', characters=characters)

@app.route('/campaigns')
def campaigns():
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '', type=str)
        per_page = 12  # Número de aventuras por página
        
        # Query base
        query = Adventure.query
        
        # Aplicar filtro de busca se fornecido
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                Adventure.title.like(search_term) |
                Adventure.description.like(search_term) |
                Adventure.requester.like(search_term)
            )
        
        # Ordenar por data de criação (mais recentes primeiro)
        query = query.order_by(Adventure.id.desc())
        
        # Aplicar paginação
        try:
            pagination = paginate_query(query, page, per_page)
            adventures = pagination.items
            pagination_info = get_pagination_info(page, per_page, pagination.total_count)
        except:
            # Fallback sem paginação
            adventures = query.all()
            pagination_info = None
            
        return render_template('campaigns.html', 
                             adventures=adventures,
                             pagination=pagination_info,
                             search=search)
                             
    except Exception as e:
        log_error('CAMPAIGNS_ERROR', str(e), current_user.id if current_user.is_authenticated else None)
        flash('Erro ao carregar campanhas.', 'error')
        return redirect(url_for('index'))


@app.route('/archive')
def archive():
    return render_template('archive.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

class Clan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    disciplines = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    slogan = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Caminho da imagem.
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Criador do 
    visible = db.Column(db.Boolean, default=False)  # Visível para todos

@app.route('/create_clan', methods=['GET', 'POST'])
@login_required
def create_clan():
    if request.method == 'POST':
        name = request.form['name']
        disciplines = request.form['disciplines']
        slogan = request.form['slogan']
        description = request.form['description']

        # Processamento de imagem
        image = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                image = f'uploads/{image_filename}'

        # Criar novo personagem importante
        new_clan = Clan(
            name=name,
            disciplines=disciplines,
            description=description,
            slogan=slogan,
            image=image,
            created_by=current_user.id
        )

        db.session.add(new_clan)
        db.session.commit()
        flash('Clã criado com sucesso!', 'success')
        return redirect(url_for('clan'))

    return render_template('clandata/create_clan.html')

@app.route('/edit_clan/<int:clan_id>', methods=['GET', 'POST'])
@login_required
def edit_clan(clan_id):
    clan = Clan.query.get_or_404(clan_id)

    # Verificar se o usuário é o criador ou um admin
    if not (current_user.is_admin or clan.created_by == current_user.id):
        abort(403)  # Proibir acesso se não for permitido

    if request.method == 'POST':
        # Atualizar detalhes do personagem
        clan.name = request.form['name']
        clan.disciplines = request.form['disciplines']
        clan.slogan = request.form['slogan']
        clan.description = request.form['description']

        # Atualizar imagem se uma nova foi enviada
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                clan.image = f'uploads/{image_filename}'

        db.session.commit()
        flash('Clã atualizado com sucesso!', 'success')
        return redirect(url_for('clan_detail', clan_id=clan.id))

    return render_template('clandata/edit_clan.html', clan=clan)

# Definição correta para delete_character
@app.route('/delete_clan/<int:clan_id>', methods=['POST'])
@login_required
def delete_clan(clan_id):
    clan = Clan.query.get_or_404(clan_id)

    # Verificar se o usuário é o criador ou um admin
    if not (current_user.is_admin or clan.created_by == current_user.id):
        abort(403)

    db.session.delete(clan)
    db.session.commit()
    flash('Clã deletado com sucesso!', 'success')
    return redirect(url_for('clan'))

# Certifique-se de que character_detail não esteja duplicado
@app.route('/clan_detail/<int:clan_id>')
def clan_detail(clan_id):
    clan = Clan.query.get_or_404(clan_id)
    return render_template('clandata/clan_detail.html', clan=clan)

@app.route('/clan')
def clan():
    clans = Clan.query.all()
    return render_template('clandata/clan.html', clans=clans)

@app.route('/disciplines')
def disciplines():
    return render_template('disciplines.html')

@app.route('/camarilla')
@login_required
def camarilla():
    return render_template('clandata/camarilla.html')

@app.route('/gear')
def gear():
    return render_template('gear.html')


@app.route('/hugo')
def hugo():
    return render_template('charactersdata/vampires/hugo.html')

@app.route('/dracula')
def dracula():
    return render_template('charactersdata/vampires/dracula.html')

@app.route('/camilla')
def camilla():
    return render_template('charactersdata/vampires/camilla.html')

@app.route('/vampires')
def vampires():
    return render_template('charactersdata/vampires/vampires.html')

@app.route('/demons')
def demons():
    return render_template('charactersdata/demons/demons.html')

@app.route('/celestials')
def celestials():
    return render_template('charactersdata/celestials/celestials.html')

@app.route('/assamitas')
def assamitas():
    return render_template('clandata/assamitas.html')

@app.route('/cainitamyth')
@login_required
def cainitamyth():
    return render_template('masters_info/cainitamyth.html')

@app.route('/saba')
def saba():
    return render_template('clandata/saba.html')


@app.route('/add_character', methods=['GET', 'POST'])
@login_required
def add_character():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        race = request.form['race']
        clan = request.form['clan']
        level = request.form['level']
        bloodline = request.form['bloodline']

        # Cria um novo personagem
        new_character = Character(name=name, description=description, race=race, clan=clan, bloodline=bloodline, level=level, user_id=current_user.id)
        
        # Adiciona ao banco de dados
        db.session.add(new_character)
        db.session.commit()
        
        return redirect(url_for('show_characters'))
    
    return render_template('character_form.html')

@app.route('/delete_charactershow/<int:id>', methods=['POST'])
@login_required
def delete_charactershow(id):
    character = Character.query.get_or_404(id)

    db.session.delete(character)
    db.session.commit()

    flash('Personagem deletado com sucesso.', 'success')
    return redirect(url_for('show_characters'))

@app.route('/edit_content', methods=['POST'])
@login_required
def edit_content():
    # Atualizar o título e a descrição
    title = request.form.get('title')
    description = request.form.get('description')

    # Buscar o conteúdo no banco de dados (aqui assumo que existe um modelo "Content")
    content = Content.query.first()
    content.title = title
    content.description = description

    # Verificar se uma nova imagem foi enviada
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            content.image = f'uploads/{filename}'

    # Salvar as alterações no banco de dados
    db.session.commit()

    flash('Conteúdo atualizado com sucesso!', 'success')
    return redirect(url_for('edit_page'))  # Redireciona para a página de edição ou exibição


@app.route('/sala_do_mestre')
@login_required
def sala_do_mestre():
    adventures = Adventure.query.all()
    music_playlist = Music.query.all()
    sfx_playlist = SFX.query.all()
    final_adventures = Adventure.query.all()
    return render_template('sala_do_mestre.html', 
                           adventures=adventures,
                           music_playlist=music_playlist,
                           sfx_playlist=sfx_playlist,
                           final_adventures=final_adventures)




@app.route('/save_final_adventure', methods=['POST'])
@login_required
def save_final_adventure():
    # Obter o ID da aventura do formulário
    adventure_id = request.form.get('adventure_id')

    if not adventure_id:
        flash("Por favor, selecione uma aventura para Finalizar.", "warning")
        return redirect(url_for('sala_do_mestre'))

    # Buscar a aventura selecionada
    try:
        adventure_id = int(adventure_id)
        adventure = Adventure.query.filter_by(id=adventure_id, status="Em andamento").first()

    except ValueError:
        flash("ID de aventura inválido.", "danger")
        return redirect(url_for('sala_do_mestre'))

    # Definir o status da aventura como finalizada
    if request.method == 'POST':
        # Atualiza os dados da aventura com os dados enviados no formulário
        adventure.finished = request.form['finished']

    adventure.responsible_user_id = current_user.id
    adventure.status = 'Finalizada'
    db.session.commit()
    
    flash("Aventura finalizada e salva com sucesso!", "success")
    return redirect(url_for('sala_do_mestre'))


class AdventureFinished(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=False)
    finished_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    finisher = db.relationship('User', foreign_keys=[finished_by])

    def __repr__(self):
        return f"<AdventureFinished {self.title}>"

# Configuração para uploads
UPLOAD_FOLDER_MUSIC = 'static/uploads/music'
UPLOAD_FOLDER_SFX = 'static/uploads/sfx'
app.config['UPLOAD_FOLDER_MUSIC'] = UPLOAD_FOLDER_MUSIC
app.config['UPLOAD_FOLDER_SFX'] = UPLOAD_FOLDER_SFX

# Função para verificar extensão de arquivo permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Modelo para Música e Efeitos Sonoros
class Music(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)

class SFX(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)

# Rota para adicionar música
@app.route('/add_music', methods=['POST'])
@login_required
def add_music():
    if 'music_file' not in request.files:
        flash('Nenhum arquivo enviado.', 'danger')
        return redirect(url_for('sala_do_mestre'))

    music_file = request.files['music_file']
    if music_file and allowed_file(music_file.filename):
        filename = secure_filename(music_file.filename)
        music_path = os.path.join(app.config['UPLOAD_FOLDER_MUSIC'], filename)
        music_file.save(music_path)

        new_music = Music(title=filename, file_path=f'uploads/music/{filename}')
        db.session.add(new_music)
        db.session.commit()

        flash('Música adicionada com sucesso!', 'success')
    else:
        flash('Formato de arquivo inválido.', 'danger')

    return redirect(url_for('sala_do_mestre'))

# Rota para adicionar efeitos sonoros
@app.route('/add_sfx', methods=['POST'])
@login_required
def add_sfx():
    if 'sfx_file' not in request.files:
        flash('Nenhum arquivo enviado.', 'danger')
        return redirect(url_for('sala_do_mestre'))

    sfx_file = request.files['sfx_file']
    if sfx_file and allowed_file(sfx_file.filename):
        filename = secure_filename(sfx_file.filename)
        sfx_path = os.path.join(app.config['UPLOAD_FOLDER_SFX'], filename)
        sfx_file.save(sfx_path)

        new_sfx = SFX(title=filename, file_path=f'uploads/sfx/{filename}')
        db.session.add(new_sfx)
        db.session.commit()

        flash('Efeito sonoro adicionado com sucesso!', 'success')
    else:
        flash('Formato de arquivo inválido.', 'danger')

    return redirect(url_for('sala_do_mestre'))

# Rota para deletar musica
@app.route('/delete_music/<int:music_id>', methods=['POST'])
@login_required
def delete_music(music_id):
    music = Music.query.get_or_404(music_id)
    if not current_user.is_admin:
        abort(403)

    # Remover o arquivo do sistema de arquivos
    music_path = os.path.join(app.root_path, 'static', music.file_path)
    if os.path.exists(music_path):
        os.remove(music_path)

    db.session.delete(music)
    db.session.commit()
    flash('Musica removido com sucesso!', 'success')

    return redirect(url_for('sala_do_mestre'))

# Rota para deletar efeito sonoro
@app.route('/delete_sfx/<int:sfx_id>', methods=['POST'])
@login_required
def delete_sfx(sfx_id):
    sfx = SFX.query.get_or_404(sfx_id)
    if not current_user.is_admin:
        abort(403)

    # Remover o arquivo do sistema de arquivos
    sfx_path = os.path.join(app.root_path, 'static', sfx.file_path)
    if os.path.exists(sfx_path):
        os.remove(sfx_path)

    db.session.delete(sfx)
    db.session.commit()
    flash('Efeito sonoro removido com sucesso!', 'success')

    return redirect(url_for('sala_do_mestre'))


# Modelo para eventos
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.String(10), nullable=False)  # Formato: YYYY-MM-DD
    time = db.Column(db.String(5), nullable=True)    # Formato: HH:MM
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_global = db.Column(db.Boolean, default=False)  # Indica se o evento é visível para todos os usuários
    
    # Relação com o usuário
    user = db.relationship('User', backref=db.backref('events', lazy=True))

# Modelo de Notificação
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'adventure', 'character', 'system'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relação com o usuário
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

@app.route('/save_event', methods=['POST'])
@login_required
def save_event():
    # Obter dados do formulário JSON
    data = request.get_json()
    
    if not data or 'title' not in data or 'date' not in data:
        return jsonify({'success': False, 'message': 'Dados incompletos'}), 400
    
    # Verificar se já existe um evento para esta data e usuário
    existing_event = Event.query.filter_by(
        date=data['date'],
        user_id=current_user.id
    ).first()
    
    # Determinar se o evento deve ser global (visível para todos)
    is_global = current_user.is_admin
    
    if existing_event:
        # Atualiza o evento existente
        existing_event.title = data['title']
        existing_event.description = data.get('description', '')
        existing_event.time = data.get('time', '')
        existing_event.is_global = is_global
        message = 'Evento atualizado com sucesso!'
    else:
        # Cria um novo evento
        new_event = Event(
            title=data['title'],
            description=data.get('description', ''),
            date=data['date'],
            time=data.get('time', ''),
            user_id=current_user.id,
            is_global=is_global
        )
        db.session.add(new_event)
        message = 'Evento criado com sucesso!'
    
    db.session.commit()
    return jsonify({'success': True, 'message': message})


@app.route('/get_events', methods=['GET'])
@login_required
def get_events():
    # Obter todos os eventos do usuário atual e eventos globais criados por administradores
    events = Event.query.filter(
        db.or_(
            Event.user_id == current_user.id,  # Eventos do usuário atual
            Event.is_global == True  # Eventos globais (criados por administradores)
        )
    ).all()
    
    # Converter para formato JSON
    events_list = [{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'date': event.date,
        'time': event.time
    } for event in events]
    
    return jsonify({'success': True, 'events': events_list})

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        adventures = Adventure.query.filter(
            Adventure.title.contains(query) | 
            Adventure.description.contains(query)
        ).all()
        characters = ImportantCharacter.query.filter(
            ImportantCharacter.name.contains(query) |
            ImportantCharacter.description.contains(query)
        ).all()
    else:
        adventures = []
        characters = []
    
    return render_template('search_results.html', 
                         adventures=adventures, 
                         characters=characters, 
                         query=query)

# Rotas para o sistema de notificações
@app.route('/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Retorna as notificações do usuário atual"""
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    notifications_data = []
    for notification in notifications:
        notifications_data.append({
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'type': notification.type,
            'is_read': notification.is_read,
            'created_at': notification.created_at.strftime('%d/%m/%Y %H:%M')
        })
    
    return jsonify(notifications_data)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Marca uma notificação como lida"""
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    
    if notification:
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Notificação não encontrada'}), 404

@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Marca todas as notificações do usuário como lidas"""
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/delete_notification/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    """Deleta uma notificação"""
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    
    if notification:
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Notificação não encontrada'}), 404

# Função auxiliar para criar notificações
def create_notification(user_id, title, message, notification_type):
    """Cria uma nova notificação para um usuário"""
    notification = Notification(
        title=title,
        message=message,
        type=notification_type,
        user_id=user_id
    )
    db.session.add(notification)
    db.session.commit()
    return notification

# Rota para criar notificações de exemplo (apenas para teste)
@app.route('/create_sample_notifications')
@login_required
def create_sample_notifications():
    """Cria notificações de exemplo para o usuário atual"""
    try:
        # Criar algumas notificações de exemplo
        create_notification(
            current_user.id,
            "Nova Aventura Disponível",
            "A aventura 'O Despertar de Lilith' foi adicionada e está disponível para participação.",
            "adventure"
        )
        
        create_notification(
            current_user.id,
            "Personagem Atualizado",
            "Seu personagem foi atualizado pelo Narrador. Verifique as mudanças em seu perfil.",
            "character"
        )
        
        create_notification(
            current_user.id,
            "Sistema Atualizado",
            "O sistema foi atualizado com novas funcionalidades. Confira o calendário de eventos!",
            "system"
        )
        
        return jsonify({'success': True, 'message': 'Notificações de exemplo criadas!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500

if __name__ == '__main__':
   
   app.run(host='0.0.0.0', port=5000, debug=True)
