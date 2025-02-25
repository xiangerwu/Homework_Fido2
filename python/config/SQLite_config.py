import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class SQLite_config:
    SECRET_KEY = "your_secret_key"
    SQLALCHEMY_DATABASE_URI = (
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'database.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
