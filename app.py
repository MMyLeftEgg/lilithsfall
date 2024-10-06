from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os


#https://sites.google.com/site/bradockrpg/vampiro-a-mascara-estruturas-vampiricas
app = Flask(__name__)

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lilith.db'  # banco de dados local
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Para proteger sessões

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

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        user = User.query.filter_by(user=user).first()

        if user and user.check_password(password):  # Verifica se a senha corresponde ao hash
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nome de usuário ou senha incorretos.', 'danger')

    return render_template('login.html')

# Rota para dashboard (requer login)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.user if current_user.is_authenticated else None)

@app.route('/admin_logins')
@login_required  # Somente usuários logados podem acessar
def admin_logins():
    if not current_user.is_admin:
        abort(403)  # Apenas admins podem acessar
    users = User.query.all()
    return render_template('admin_logins.html', users=users)

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

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu com sucesso.', 'info')
    return redirect(url_for('login'))

# Rota de registro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        email = request.form['email']

        # Cria um novo usuário e hashea a senha
        new_user = User(user=user, email=email)
        new_user.set_password(password)  # Hashear a senha antes de salvar
        db.session.add(new_user)
        db.session.commit()

        new_user = User(user=user)

        flash('Registro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

class Adventure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    requester = db.Column(db.String(100), nullable=False)
    reward = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    document = db.Column(db.String(255), nullable=True)  # Caminho do documento anexado
    image = db.Column(db.String(255), nullable=True)     # Caminho da imagem anexada

    def __repr__(self):
        return f"<Adventure {self.title}>"
    
    # Configuração para o upload
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Função para verificar extensão de arquivo
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/create_adventure', methods=['GET', 'POST'])
@login_required
def create_adventure():
    if request.method == 'POST':
        title = request.form['title']
        requester = request.form['requester']
        reward = request.form['reward']
        description = request.form['description']

        # Upload de documento e imagem
        document = None
        image = None
        
        if 'document' in request.files:
            doc = request.files['document']
            if doc and allowed_file(doc.filename):
                document_filename = secure_filename(doc.filename)
                doc.save(os.path.join(app.config['UPLOAD_FOLDER'], document_filename))
                document = f'uploads/{document_filename}'
        
        if 'image' in request.files:
            img = request.files['image']
            if img and allowed_file(img.filename):
                image_filename = secure_filename(img.filename)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                image = f'uploads/{image_filename}'

        # Criar nova aventura e salvar no banco de dados
        new_adventure = Adventure(title=title, requester=requester, reward=reward,
                                  description=description, document=document, image=image)
        db.session.add(new_adventure)
        db.session.commit()

        flash('Aventura criada com sucesso!', 'success')
        return redirect(url_for('campaigns'))

    return render_template('create_adventure.html')

@app.route('/adventure/<int:adventure_id>')
def adventure_detail(adventure_id):
    adventure = Adventure.query.get_or_404(adventure_id)
    return render_template('adventure_detail.html', adventure=adventure)

    
# Modelo para campos editaveis
class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(000), nullable=False)


# Modelo para personagem
class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    race = db.Column(db.String(200))
    mask = db.Column(db.String(200))
    clan = db.Column(db.String(200))
    bloodline = db.Column(db.String(200))
    description = db.Column(db.String(200))

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
    return render_template('characters.html')

@app.route('/campaigns')
def campaigns():
    adventures = Adventure.query.all()
    return render_template('campaigns.html', adventures=adventures)


@app.route('/archive')
def archive():
    return render_template('archive.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/clan')
def clan():
    return render_template('clan.html')

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

@app.route('/leo')
def leo():
    return render_template('charactersdata/humans/leo.html')


@app.route('/add_character', methods=['GET', 'POST'])
def add_character():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        race = request.form['race']
        mask = request.form['mask']
        clan = request.form['clan']
        bloodline = request.form['bloodline']


        
        # Cria um novo personagem
        new_character = Character(name=name, description=description, race=race, mask=mask, clan=clan, bloodline=bloodline)
        
        # Adiciona ao banco de dados
        db.session.add(new_character)
        db.session.commit()
        
        return redirect(url_for('show_characters'))
    
    return render_template('character_form.html')

@app.route('/delete_character/<int:id>', methods=['POST'])
@login_required
def delete_character(id):
    character = Character.query.get_or_404(id)

    db.session.delete(character)
    db.session.commit()

    flash('Personagem deletado com sucesso.', 'success')
    return redirect(url_for('show_characters'))

# Diretório onde as imagens serão salvas
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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



if __name__ == '__main__':
   
   app.run(host='0.0.0.0', port=5000, debug=True)
