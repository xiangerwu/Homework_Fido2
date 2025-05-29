import os
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
- /  入口網站首頁
"""
# 入口
@app.route("/")
@attach_jwt_if_available
def home():
    payload = request.jwt_payload
    #  username = payload.get("username") if payload else None
    username = ("username", "一般使用者")
    # 如果 payload 有值，代表有登入，否則沒有登入
    if payload:
        # print(f"登入使用者: {username}")
        #login_level = payload.get("login_level", 0)  # 預設登入等級為 0
        login_level = 1  # 先預設等級為 1，後續可以根據實際情況調整
        if login_level == 0:
            print("登入等級為 0，無法存取")
            return jsonify({"error": "無權限存取"}), 403
        else:
            print(f"登入等級: {login_level}")
            # 根據登入等級決定顯示的內容
            if login_level == 1:
                print("使用者為一般使用者")
            elif login_level == 2:
                print("使用者為管理員")
            elif login_level == 3:
                print("使用者為超級管理員")
    else:
        print("未登入或無效的 JWT Token")
        login_level = 0  # 沒有登入，登入等級為 0


    return render_template("index.html", username=username, login_level=login_level)




@app.route("/register-begin", methods=["POST"])
def register_begin():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify(success=False, message="請提供用戶名稱"), 400

    try:
        # ✅ 發送 POST 請求給外部 API
        response = requests.post(
            "https://127.0.0.1:1919/register-begin",  # <== 替換成目標 API 的 URL
            json={"username": username},
            timeout=60,
            verify="server_key/server.crt"
        )

        try:
            result = response.json()
        except ValueError:
            # 🧨 JSON 解析失敗
            print("⚠️ PDP 回傳非 JSON：", response.text)
            return jsonify({"error": "PDP 回傳格式錯誤", "raw": response.text}), 502

        if response.status_code == 200:
            return jsonify(result), 200
        else:
            # ⚠️ PDP 有回應但失敗，附加原始訊息
            return jsonify({
                "error": "PDP 錯誤回應",
                "status": response.status_code,
                "message": result.get("error", "未知錯誤"),
                "raw": result
            }), 502
            

    except requests.RequestException as e:
        print("❌ PDP 連線失敗：", e)
        return jsonify({"error": "無法連接 PDP", "detail": str(e)}), 503


@app.route("/register-end", methods=["POST"])
def register_end():
    data = request.get_json()
    username = data.get("username")
    credential = data.get("credential")
    if not username or not credential:
        return jsonify(success=False, message="請提供用戶名稱與憑證資料"), 400

    try:
        # ✅ 發送 POST 請求給 PDP 的 /register-end API
        response = requests.post(
            "https://127.0.0.1:1919/register-end",  # 替換為 PDP 的真實網址
            json={
                "username": username,
                "credential": credential
            },
            timeout=60,
            verify="server_key/server.crt"
        )

        # ✅ 處理 PDP 的回傳
        if response.status_code == 200:
            result = response.json()
            return jsonify(success=True, message=result.get("message", "註冊完成")), 200
        else:
            return jsonify(success=False, message=result.get("error", "未知錯誤"), debug=result.get("debug", [])), 400
    

    except requests.RequestException as e:
        print(f"❌ 無法送出憑證資料：{e}")
        return jsonify(success=False, message="無法連接憑證服務"), 503
    

@app.route("/login-begin", methods=["POST"])
def login_begin():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify(error="請提供用戶名稱"), 400

    try:
        # ✅ 將使用者資訊傳遞給 PDP
        response = requests.post(
            "https://127.0.0.1:1919/login-begin",  # <== 改成你的 PDP API
            json={"username": username},
            timeout=60,
            verify="server_key/server.crt"
        )

        if response.status_code == 200:
            options = response.json()
            return jsonify(options), 200
        else:
            return jsonify(error="❌ PDP 錯誤：" + response.text), 502

    except requests.RequestException as e:
        return jsonify(error=f"無法連線 PDP：{str(e)}"), 503

@app.route("/login-end", methods=["POST"])
def login_end():
    data = request.get_json()
    username = data.get("username")
    credential = data.get("credential")

    if not username or not credential:
        return jsonify(error="請提供用戶名稱與憑證資料"), 400

    try:
        # ✅ 傳送憑證資料至 PDP 做驗證
        response = requests.post(
            "https://127.0.0.1:1919/login-end",  # <== 改成 PDP API
            json={
                "username": username,
                "credential": credential,
                "source": "akitawan.moe",
                "dist": "akitawan.moe"
            },
            timeout=60,
            verify="server_key/server.crt"
        )

        if response.status_code == 200:
            result = response.json()
            token = result.get("token")

            if not token:
                return jsonify(error="驗證成功但未收到 token"), 500

            # ✅ 建立回應並寫入 cookie
            resp = make_response(jsonify({"status": "OK", "message": "登入成功"}))
            resp.set_cookie(
                "pdp_token", token,
                max_age=3600,
                httponly=True,
                secure=True,
                samesite="None",
                path="/"
            )
            return resp
        else:
            return jsonify(error="❌ PDP 驗證錯誤：" + response.text), 502

    except requests.RequestException as e:
        return jsonify(error=f"登入過程連線 PDP 失敗：{str(e)}"), 503

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

