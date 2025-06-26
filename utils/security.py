import os
import re
from werkzeug.utils import secure_filename
from markupsafe import escape
from functools import wraps
from flask import request, jsonify, current_app
from flask_login import current_user
from datetime import datetime, timedelta
import hashlib

# Rate limiting storage
rate_limit_storage = {}

def sanitize_input(text):
    """Sanitiza entrada de texto para prevenir XSS"""
    if not text:
        return text
    return escape(text)

def validate_file_upload(file):
    """Validação robusta de upload de arquivos"""
    if not file or not file.filename:
        return False, "Nenhum arquivo selecionado"
    
    # Verificar extensão
    allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'})
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in allowed_extensions:
        return False, f"Extensão {ext} não permitida"
    
    # Verificar tamanho (usar configuração da app)
    max_size = current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB default
    file.seek(0, 2)  # Ir para o final
    size = file.tell()
    file.seek(0)  # Voltar ao início
    if size > max_size:
        return False, f"Arquivo muito grande (máximo {max_size // (1024*1024)}MB)"
    
    # Verificar assinatura do arquivo (magic numbers)
    header = file.read(512)
    file.seek(0)
    
    # Assinaturas básicas de arquivos
    signatures = {
        b'\x89PNG\r\n\x1a\n': ['png'],
        b'\xff\xd8\xff': ['jpg', 'jpeg'],
        b'GIF8': ['gif'],
        b'%PDF': ['pdf'],
        b'PK\x03\x04': ['docx'],  # ZIP-based formats
        b'ID3': ['mp3'],
        b'RIFF': ['wav'],
        b'OggS': ['ogg']
    }
    
    valid_signature = False
    for sig, file_types in signatures.items():
        if header.startswith(sig) and ext in file_types:
            valid_signature = True
            break
    
    if not valid_signature and ext in ['png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp3', 'wav', 'ogg']:
        return False, "Arquivo corrompido ou tipo inválido"
    
    return True, "Arquivo válido"

def secure_file_save(file, upload_folder, subfolder=None):
    """Salva arquivo de forma segura"""
    if not file:
        return None
    
    # Validar arquivo
    is_valid, message = validate_file_upload(file)
    if not is_valid:
        raise ValueError(message)
    
    # Gerar nome seguro
    filename = secure_filename(file.filename)
    
    # Adicionar timestamp para evitar conflitos
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{name}_{timestamp}{ext}"
    
    # Criar diretório se necessário
    save_path = upload_folder
    if subfolder:
        save_path = os.path.join(upload_folder, subfolder)
    
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    
    # Salvar arquivo
    file_path = os.path.join(save_path, filename)
    file.save(file_path)
    
    # Retornar caminho relativo para o banco
    relative_path = os.path.join('uploads', subfolder, filename) if subfolder else os.path.join('uploads', filename)
    return relative_path.replace('\\', '/')

def validate_password_strength(password):
    """Valida força da senha"""
    if len(password) < 8:
        return False, "Senha deve ter pelo menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "Senha deve conter pelo menos uma letra maiúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "Senha deve conter pelo menos uma letra minúscula"
    
    if not re.search(r'\d', password):
        return False, "Senha deve conter pelo menos um número"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Senha deve conter pelo menos um caractere especial"
    
    return True, "Senha válida"

def rate_limit(max_requests=5, window_minutes=15):
    """Decorator para rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Identificar cliente (IP + user_id se logado)
            client_id = request.remote_addr
            if current_user.is_authenticated:
                client_id += f"_user_{current_user.id}"
            
            # Chave para esta função específica
            key = f"{f.__name__}_{client_id}"
            
            now = datetime.now()
            window_start = now - timedelta(minutes=window_minutes)
            
            # Limpar entradas antigas
            if key in rate_limit_storage:
                rate_limit_storage[key] = [
                    timestamp for timestamp in rate_limit_storage[key]
                    if timestamp > window_start
                ]
            else:
                rate_limit_storage[key] = []
            
            # Verificar limite
            if len(rate_limit_storage[key]) >= max_requests:
                return jsonify({
                    'error': 'Muitas tentativas. Tente novamente mais tarde.',
                    'retry_after': window_minutes * 60
                }), 429
            
            # Adicionar timestamp atual
            rate_limit_storage[key].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_email(email):
    """Valida formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def generate_csrf_token():
    """Gera token CSRF"""
    import secrets
    return secrets.token_urlsafe(32)

def hash_file_content(file_path):
    """Gera hash do conteúdo do arquivo para verificação de integridade"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return None

def clean_filename(filename):
    """Limpa nome de arquivo removendo caracteres perigosos"""
    # Remove caracteres perigosos
    filename = re.sub(r'[^\w\s.-]', '', filename)
    # Remove espaços múltiplos
    filename = re.sub(r'\s+', '_', filename)
    # Limita tamanho
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    return filename