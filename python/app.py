import os
from flask import Flask
from flask_cors import CORS
from flask_sslify import SSLify
from flask_sqlalchemy import SQLAlchemy
from config.config import Config

SQLite_db = SQLAlchemy()


def create_app():
    """建立 Flask 應用"""
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, origins="*", supports_credentials=True)
    SSLify(app)

    SQLite_db.init_app(app)

    # 註冊 Blueprint (分離的 API 路由)
    from routes.auth_routes import auth_bp
    from routes.user_routes import user_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(user_bp, url_prefix="/users")

    return app
