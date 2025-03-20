from config.global_config import *
from Database.db_manager import DatabaseManager
from flask import Flask, render_template, jsonify, request, redirect
from flask_cors import CORS
from flask_sslify import SSLify
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
import hashlib

# 引入全域變數
fido2_rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)

# FIDO2 伺服器
server = Fido2Server(fido2_rp, attestation="DIRECT")

# 創建 Flask 應用，設定靜態資料夾與模板資料夾
app = Flask(__name__, static_folder="static", template_folder="templates")

# 設定 CORS 跨域請求
# if os.getenv("GAE_ENV", ""):
CORS(app, origins=["https://akitawan.moe", "https://fido2_web.akitawan.moe"])
# else:
#     CORS(app, ORIGIN="*", supports_credentials=True)

# 設定 SSL
sslify = SSLify(app)

# 設定 secret_key
app.secret_key = g_secret_key


""" 註冊路由部份 """


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
    # 預設密碼
    predefined_password = "1145141919810"
    # 將預設密碼進行 SHA-256 加密
    hashed_predefined_password = hashlib.sha256(
        predefined_password.encode("utf-8")
    ).hexdigest()
    # 從前端接收加密的密碼（應該已經經過 SHA-256 加密）
    hashed_password_from_frontend = request.data.decode("utf-8").strip('"')

    # 比對前端傳來的密碼哈希與預設密碼哈希
    if hashed_password_from_frontend == hashed_predefined_password:
        try:
            # 清除資料庫
            with DatabaseManager(db_users) as db:
                db.delete_all()
            return jsonify({"status": "ok", "message": "用戶資料已清除"})
        except Exception as e:
            # 如果發生錯誤，則返回錯誤訊息
            return jsonify({"status": "error", "error": f"清除用戶資料失敗: {e}"})
    else:
        # 如果密碼不正確，則返回錯誤訊息
        return jsonify({"status": "error", "error": "密碼錯誤"})


# __name__ == "__main__" 代表你執行這個模塊時，它才會運行app.run()
# 通常用於測試，當模塊被引入到其他模塊或程式時，app.run()不會運行
if __name__ == "__main__":
    # 引入拆分的路由
    from routes.register import register_bp
    from routes.auth import auth_bp

    # 用於註冊的路由
    app.register_blueprint(register_bp, url_prefix="/register")
    # 用於驗證的路由
    app.register_blueprint(auth_bp, url_prefix="/auth")

    # app.run(host=g_IP, port=g_port, debug=True, ssl_context=(g_SSL_crt, g_SSL_key))
    app.run(host=g_IP, port=g_port, debug=True)