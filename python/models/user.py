from flask_sqlalchemy import SQLAlchemy

SQL_db = SQLAlchemy()


class User(SQL_db.Model):
    id = SQL_db.Column(SQL_db.Integer, primary_key=True)
    username = SQL_db.Column(SQL_db.String(80), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "username": self.username}
