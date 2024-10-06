from app import db, app  # Importa o app e o db corretamente
# Cria o banco de dados dentro do contexto da aplicação
with app.app_context():
    db.create_all()
print("Banco de dados criado com sucesso!")