from config.global_config import *
from Database.db_manager import DatabaseManager
from flask import Flask, render_template, jsonify, request, make_response,send_from_directory
from flask_cors import CORS
from flask_sslify import SSLify
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from werkzeug.middleware.proxy_fix import ProxyFix

# 引入全域變數
fido2_rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)

# FIDO2 伺服器
server = Fido2Server(fido2_rp, attestation="DIRECT")

# 創建 Flask 應用，設定靜態資料夾與模板資料夾
app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
# 設定 CORS 跨域請求
CORS(app, origins=ORIGIN, supports_credentials=True)
# 設定 SSL
sslify = SSLify(app)

# 設定 secret_key
app.secret_key = g_secret_key

""" 註冊路由部份 """
"""
現有路由列表
- /  首頁
- /main  主要測試頁面
- /oauth  測試 oauth 
- /users  取得所有用戶資料
- /clear  清除測試用戶資料
- /logout  登出
- /oauth2/authorize  OAuth 認證頁面
- /.well-known/jwks.json  JWKS 公鑰
- 
"""
# icon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static/images'),
        'favicon.png',
        mimetype='image/png'
    )

# 首頁
@app.route("/")
def home():
    return render_template("index.html")

# 主要測試頁面
@app.route("/main")
@attach_jwt_if_available
def main():
    return render_template("main.html", user=request.jwt_payload, user_error = request.jwt_error)

# 測試 oauth
@app.route("/oauth2")
def oauth():
    return render_template("oauth_login.html")


# 取得所有用戶資料
@app.route("/users", methods=["GET"])
def users():
    user_list = []
    with DatabaseManager(db_users) as db:
        users = db.get_all_users()
        for user in users:
            user_list.append(
                {
                    "id": user[0],
                    "username": unsanitize_username(user[1]),
                    "registeredAt": user[3],
                }
            )
    return jsonify(user_list)



# 登出
@app.route("/logout", methods=["POST"])
def logout():
    print("🧼 清除 A 的 token cookie")
    response = make_response(jsonify({"status": "ok", "message": "已登出"}))
    response.set_cookie("token", "", max_age=0, secure=True, samesite="None", path="/")
    return response


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
    from routes.authentication import auth_bp
    from routes.oauth2 import oauth_bp
    # 用於註冊的路由
    app.register_blueprint(register_bp, url_prefix="/register")
    # 用於驗證的路由
    app.register_blueprint(auth_bp, url_prefix="/authentication")
    # 用於 OAuth 的路由
    app.register_blueprint(oauth_bp, url_prefix="/oauth2")
    
    # app.run(host=g_IP, port=g_port, debug=True, ssl_context=(g_SSL_crt, g_SSL_key))
    app.run(host=g_IP, port=g_port, debug=True)
