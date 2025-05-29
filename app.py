from config.global_config import *
from flask import Flask, render_template, jsonify, request, make_response,send_from_directory
from flask_cors import CORS
from flask_sslify import SSLify

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.exceptions import NotFound
import hashlib

# 創建 Flask 應用，設定靜態資料夾與模板資料夾
app = Flask(__name__, 
             static_folder="static", 
            template_folder="templates"
        )

# app.config["APPLICATION_ROOT"] = "/" 
app.wsgi_app = ProxyFix(app.wsgi_app,  x_for=1, x_proto=1,x_host=1,x_prefix=1)

# 設定 CORS 跨域請求
CORS(app, origins=ORIGIN, supports_credentials=True)
# 設定 SSL
sslify = SSLify(app)

# 設定 secret_key
app.secret_key = g_secret_key

""" 註冊路由部份 """
"""
現有路由列表
- /login_decision: 用於處理登入決策的路由
"""

# 將來源確認邏輯抽出成共用函式
def verify_source():
    allowed_sources = ["akitawan.moe"]  # 可根據實際需求調整
    source_ip = request.remote_addr
    print(f"🔍 來源 IP: {source_ip}")
    return True  # 暫時允許所有來源，後續可強化檢查


# 登入決策
# 除非有路由不然一律404
@app.route("/", methods=["GET", "POST"])
def index():
    # 404 Not Found
    return render_template("index.html")

""" 註冊路由-開始 """
@app.route("/register-begin", methods=["POST"])
def register_begin():
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "缺少用戶名稱"}), 400

    try:
        res = requests.post(
            PIPS["Fido2"]+"register-begin",
            json={"username": username},
            timeout=10,
            verify=False  # 使用 FIDO2 的公鑰憑證
        )
        return jsonify(res.json()), res.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"連接 FIDO2 伺服器失敗：{str(e)}"}), 503
    


""" 註冊路由-結束 """
@app.route("/register-end", methods=["POST"])
def register_end():
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    try:
        res = requests.post(
            PIPS["Fido2"]+"register-end",
            json=data,
            timeout=10,
            verify="server_key/server.crt"  # 使用 FIDO2 的公鑰憑證
        )
        return jsonify(res.json()), res.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"連接 FIDO2 伺服器失敗：{str(e)}"}), 503
    
""" 登入路由-開始 """
@app.route("/login-begin", methods=["POST"])
def login_begin():
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "缺少用戶名稱"}), 400

    try:
        res = requests.post(
            PIPS["Fido2"]+"login-begin",
            json={"username": username},
            timeout=10,
            verify="server_key/server.crt"  # 使用 FIDO2 的公鑰憑證
        )
        return jsonify(res.json()), res.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"連接 FIDO2 伺服器失敗：{str(e)}"}), 503

""" 登入路由-結束 """
@app.route("/login-end", methods=["POST"])
def login_end():
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    credential = data.get("credential")

    if not username or not credential:
        return jsonify({"error": "請提供用戶名稱與憑證資料"}), 400

    try:
        res = requests.post(
            PIPS["Fido2"]+"login-end",
            json={
                "username": username,
                "credential": credential,
                "source": "card.example.com",
                "dist": "fido2.example.com"
            },
            timeout=10,
            verify="server_key/server.crt"  # 使用 FIDO2 的公鑰憑證
        )
        if res.status_code == 200:
            result = res.json()
            token = result.get("token")
            if token:
                resp = make_response(jsonify(result), 200)
                resp.set_cookie("fido2_token", token, max_age=3600, httponly=True)
                return resp
            return jsonify(result), 200
        else:
            return jsonify({"error": "FIDO2 伺服器驗證失敗", "details": res.text}), 502
    except requests.RequestException as e:
        return jsonify({"error": f"登入過程連線 FIDO2 失敗：{str(e)}"}), 503



#判斷存取來源
@app.route("/check_origin")
def check_origin():
    # 取得請求的來源
    origin = request.headers.get("Origin")
    print(f"請求來源: {origin}")

    # 檢查來源是否在允許的列表中
    if origin in ORIGIN:
        return jsonify({"message": "合法來源"}), 200
    else:
        return jsonify({"message": "非法來源"}), 403

# 主要測試頁面
# 反代理路由
# application = DispatcherMiddleware(Flask("dummy"), {
#     '/': app
# })
application = app

# __name__ == "__main__" 代表你執行這個模塊時，它才會運行app.run()
# 通常用於測試，當模塊被引入到其他模塊或程式時，app.run()不會運行
if __name__ == "__main__":
    # app.run(host=g_IP, port=g_port, debug=True, ssl_context=(g_SSL_crt, g_SSL_key))
    app.run(host=g_IP, port=g_port, debug=True)



