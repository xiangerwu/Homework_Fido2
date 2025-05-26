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

