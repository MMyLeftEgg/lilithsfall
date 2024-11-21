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
    is_admin = db.Column(db.Boolean, default=True)


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
    # Se o usuário já está autenticado, redirecione para a dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Se o método é POST, tentamos realizar o login
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        
        # Busca o usuário pelo nome de usuário
        user = User.query.filter_by(user=user).first()

        # Verifica se o usuário existe e se a senha está correta
        if user and check_password_hash(user.password, password):  # Idealmente usando senha com hash
            login_user(user)
            flash('Login bem-sucedido!', 'success')

            # Redireciona para a página pretendida ou dashboard
            next_page = request.args.get('next')  # Obtém a próxima página se o login foi exigido
            return redirect(next_page) if next_page else redirect(url_for('index'))
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

@app.route('/create_adventure', methods=['GET', 'POST'])
@login_required
def create_adventure():
    if request.method == 'POST':
        title = request.form['title']
        requester = request.form['requester']
        reward = request.form['reward']
        description = request.form['description']
        document = None
        image = None

        # Processamento de arquivos
        if 'document' in request.files:
            document_file = request.files['document']
            if document_file and allowed_file(document_file.filename):
                document_filename = secure_filename(document_file.filename)
                document_path = os.path.join(app.config['UPLOAD_FOLDER'], 'documents', document_filename)
                document_file.save(document_path)
                document = f'uploads/documents/{document_filename}'

        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', image_filename)
                image_file.save(image_path)
                image = f'uploads/images/{image_filename}'

        # Criar nova aventura e salvar no banco de dados
        new_adventure = Adventure(
            title=title,
            requester=requester,
            reward=reward,
            description=description,
            document=document,
            image=image,
            creator_id=current_user.id  # Define o criador da aventura como o usuário atual
            
        )
        db.session.add(new_adventure)
        db.session.commit()

        flash('Aventura criada com sucesso!', 'success')
        return redirect(url_for('campaigns'))

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
    adventures = Adventure.query.filter_by(status=status).all()
    return render_template('show_adventures.html', adventures=adventures, status=status)

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
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Caminho da imagem
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Criador do personagem

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
            image=image,
            created_by=current_user.id
        )

        db.session.add(new_character)
        db.session.commit()
        flash('Personagem criado com sucesso!', 'success')
        return redirect(url_for('show_characters_by_race', race=race))

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
    race = db.Column(db.String(200))
    mask = db.Column(db.String(200))
    clan = db.Column(db.String(200))
    level = db.Column(db.Integer)
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

class Clan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    disciplines = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    slogan = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Caminho da imagem.
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Criador do 

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
def add_character():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        race = request.form['race']
        clan = request.form['clan']
        level = request.form['level']
        bloodline = request.form['bloodline']

        # Cria um novo personagem
        new_character = Character(name=name, description=description, race=race, clan=clan, bloodline=bloodline, level=level)
        
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
        adventure = Adventure.query.all()

    except ValueError:
        flash("ID de aventura inválido.", "danger")
        return redirect(url_for('sala_do_mestre'))

    # Definir o usuário atual como responsável pela aventura
    adventure.status = "Finalizada"
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


if __name__ == '__main__':
   
   app.run(host='0.0.0.0', port=5000, debug=True)
