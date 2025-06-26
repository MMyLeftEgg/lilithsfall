import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

def setup_logging(app):
    """Configura o sistema de logging da aplicação"""
    
    if not app.debug:
        # Criar diretório de logs se não existir
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Configurar handler para arquivo de log
        file_handler = RotatingFileHandler(
            'logs/lilithsfall.log', 
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Lilith\'s Fall startup')

def log_user_action(user_id, action, details=None):
    """Log de ações do usuário para auditoria"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] User {user_id}: {action}"
    if details:
        log_entry += f" - {details}"
    
    # Criar diretório de logs de auditoria se não existir
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    with open('logs/user_actions.log', 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')

def log_security_event(event_type, details, user_id=None):
    """Log de eventos de segurança"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] SECURITY - {event_type}: {details}"
    if user_id:
        log_entry += f" (User: {user_id})"
    
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    with open('logs/security.log', 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')

def log_error(error_type, error_message, user_id=None):
    """Log de erros da aplicação"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] ERROR - {error_type}: {error_message}"
    if user_id:
        log_entry += f" (User: {user_id})"
    
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    with open('logs/errors.log', 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')