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


# 登入決策
@app.route("/")
@app.route("/login_decision")
@attach_jwt_if_available_only_sign
def decision():
    print("進入登入決策頁面")
    payload = request.jwt_payload  # 裝飾器已經驗簽好

    if payload:
        print("JWT Token 驗簽成功:", payload)
        resp = make_response(render_template("post_login_close.html", redirect_url="https://proxy.akitawan.moe"))
        # 如您仍需重新簽發 JWT，可在這裡執行
        token = request.cookies.get("token")  # 可選：取得原 token 用來寫回
        if token:
            resp.set_cookie("token", token, httponly=True, secure=True)
        return resp
    else:
        print("未檢測到 token 或驗簽失敗，顯示登入頁面")
        return render_template("popup_redirect.html")



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

