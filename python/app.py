from global_config import *
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_sslify import SSLify

# 引入拆分的路由
from routes.register import register_bp
from routes.auth import auth_bp

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)
sslify = SSLify(app)
#
app.secret_key = g_secret_key

# 註冊路由
app.register_blueprint(register_bp, url_prefix="/register")
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route("/")
def home():
    return """Hello, World! <a href="/main">點擊進入 WebAuthn 環節</a>"""


@app.route("/main")
def main():
    return render_template("index.html")


@app.route("/clear", methods=["POST"])
def clear():
    users.clear()
    return jsonify({"status": "ok", "message": "用戶資料已清除"})


if __name__ == "__main__":
    app.run(
        host=g_IP,
        port=g_Port,
        debug=True,
        ssl_context=(g_SSL_crt, g_SSL_key),
    )
