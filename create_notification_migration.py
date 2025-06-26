#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para criar migração da tabela de notificações
"""

import os
import sys
from datetime import datetime

# Adicionar o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade, migrate
from app import app, db

def create_migration():
    """Cria a migração para a tabela de notificações"""
    try:
        with app.app_context():
            # Criar migração
            print("Criando migração para o modelo Notification...")
            
            # Executar migração
            from flask_migrate import migrate as flask_migrate
            flask_migrate(message="Adicionar modelo Notification")
            
            print("Migração criada com sucesso!")
            
            # Aplicar migração
            print("Aplicando migração...")
            upgrade()
            print("Migração aplicada com sucesso!")
            
    except Exception as e:
        print(f"Erro ao criar/aplicar migração: {e}")
        
        # Tentar criar a tabela manualmente
        print("Tentando criar a tabela manualmente...")
        try:
            db.create_all()
            print("Tabelas criadas com sucesso!")
        except Exception as e2:
            print(f"Erro ao criar tabelas: {e2}")

if __name__ == '__main__':
    create_migration()