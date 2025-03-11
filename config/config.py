import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = (
        f"sqlite:///{os.path.join(BASE_DIR, '../instance/database.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RP_ID = "127.0.0.1"
    RP_NAME = "My WebAuthn App"
    ORIGIN = "127.0.0.1:5000"
    SSL_CERT = "../../SSL_file/server.crt"
    SSL_KEY = "../../SSL_file/server.key"
