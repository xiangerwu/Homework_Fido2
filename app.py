from config.global_config import *
from config.db_manager import DatabaseManager
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_sslify import SSLify
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# 引入全域變數
fido2_rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(fido2_rp, attestation="DIRECT")

# 引入拆分的路由
from routes.register import register_bp
from routes.auth import auth_bp

app = Flask(__name__, static_folder="static", template_folder="templates")
# 設定 CORS 跨域請求

CORS(app, origins=["https://akitawan.moe", "https://fido2.akitawan.moe"])
# CORS(app, ORIGIN="*", supports_credentials=True)

# 設定 SSL
sslify = SSLify(app)

app.secret_key = g_secret_key

"""引入拆分註冊路由區塊"""
# 用於註冊的路由
app.register_blueprint(register_bp, url_prefix="/register")
# 用於驗證的路由
app.register_blueprint(auth_bp, url_prefix="/auth")


""" 註冊路由部份 """  # """


# 首頁
@app.route("/")
def home():
    return """Hello, World! <a href="/main">點擊進入 WebAuthn 環節</a>"""


# 主要測試頁面
@app.route("/main")
def main():
    return render_template("index.html")


# 取得所有用戶資料
@app.route("/users", methods=["GET"])
def users():
    user_list = []
    with DatabaseManager(db_users) as db:
        users = db.get_all_users()
        for user in users:
            user_list.append(
                {"id": user[0], "username": user[1], "registeredAt": user[3]}
            )
    return jsonify(user_list)


# 清除測試用戶資料
@app.route("/clear", methods=["POST"])
def clear():
    try:
        # 清除資料庫
        with DatabaseManager(db_users) as db:
            db.delete_all()
        return jsonify({"status": "ok", "message": "用戶資料已清除"})
    except Exception as e:
        # 如果發生錯誤，則返回錯誤訊息
        return jsonify({"status": "error", "message": f"清除用戶資料失敗: {e}"})


# __name__ == "__main__" 代表你執行這個模塊時，它才會運行app.run()
# 通常用於測試，當模塊被引入到其他模塊或程式時，app.run()不會運行
if __name__ == "__main__":

    # 設定 IP 與 Port、啟用 debug 模式、並使用 SSL 憑證、金鑰
    app.run(
        host=g_IP,
        port=g_Port,
        debug=True,
        # ssl_context=(g_SSL_crt, g_SSL_key), 託管在 Render  不需要 SSL
    )
