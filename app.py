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
    if payload:
        username = payload.get("sub")  # ✅ 這時 payload 是 dict，才有 .get
    else:
        username = None  # 或者給預設值，如 "未登入"
    # 如果 payload 有值，代表有登入，否則沒有登入
    if payload:
        log(f"登入使用者: {username}")
        login_level = payload.get("login_level", 0)  # 預設登入等級為 0
        # login_level = 1  # 先預設等級為 1，後續可以根據實際情況調整
        if login_level == 0:
            log("登入等級為 0，無法存取")
            return jsonify({"error": "無權限存取"}), 403
        else:
            log(f"登入等級: {login_level}")
            # 根據登入等級決定顯示的內容
            if login_level == 1:
                log("使用者為一般使用者")
            elif login_level == 2:
                log("使用者為管理員")
            elif login_level == 3:
                log("使用者為超級管理員")
    else:
        log("未登入或無效的 JWT Token")
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
        log("🔗 正在連接 PDP 註冊開始 API...")
        response = requests.post(
            PDP+"register-begin",  # <== 替換成目標 API 的 URL
            json={"username": username},
            timeout=10,
            verify=False
        )
        log("🔗 連接 PDP 註冊開始 API 完成，處理回應...")
        try:
            result = response.json()
        except ValueError:
            # 🧨 JSON 解析失敗
            log("⚠️ PDP 回傳非 JSON：", response.text)
            return jsonify({"error": "PDP 回傳格式錯誤", "raw": response.text}), 502

        # ✅ 檢查回應狀態碼
        if response.status_code == 200:
            # 🟢 成功取得 PDP 回應
            # 回傳給前端
            log("✅ PDP 回應成功：", result)
            return jsonify(result), 200
        else:
            # ⚠️ PDP 有回應但失敗，附加原始訊息
            log("⚠️ PDP 回應錯誤：", result)
            return jsonify({
                "error": "PDP 錯誤回應",
                "status": response.status_code,
                "message": result.get("error", "未知錯誤"),
                "raw": result
            }), 502
            

    except requests.RequestException as e:
        log("❌ PDP 連線失敗：", e)
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
        log("🔗 正在連接 PDP 完成註冊 API...")
         # 替換為 PDP 的真實網址
        response = requests.post(
            PDP+"register-end",  # 替換為 PDP 的真實網址
            json={
                "username": username,
                "credential": credential
            },
            timeout=10,
            verify=False
        )

        # ✅ 處理 PDP 的回傳
        log("🔗 連接 PDP 完成註冊 API 完成，處理回應...")
        if response.status_code == 200:
            log("✅ PDP 回應成功，解析 JSON...")
            log("PDP 回應內容：", response.text)
            result = response.json()
            return jsonify(success=True, message=result.get("message", "註冊完成")), 200
        else:
            log("⚠️ PDP 回應錯誤，狀態碼：", response.status_code)
            log("PDP 回應內容：", response.text)
            return jsonify(success=False, message=result.get("error", "未知錯誤"), debug=result.get("debug", [])), 400
    

    except requests.RequestException as e:
        log(f"❌ 無法送出憑證資料：{e}")
        return jsonify(success=False, message="無法連接憑證服務"), 503
    

@app.route("/login-begin", methods=["POST"])
def login_begin():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify(error="請提供用戶名稱"), 400

    try:
        # ✅ 將使用者資訊傳遞給 PDP
        log("🔗 正在連接 PDP 登入開始 API...")
        response = requests.post(
            PDP+"login-begin",  # <== 改成你的 PDP API
            json={"username": username},
            timeout=10,
            verify=False
        )
        log("🔗 連接 PDP 登入開始 API 完成，處理回應...")
        if response.status_code == 200:
            log("✅ PDP 登入開始 API 回應成功，解析 JSON...")
            log("PDP 回應內容：", response.text)
            options = response.json()
            return jsonify(options), 200
        # 如果 PDP 回應錯誤，回傳錯誤訊息
        else:
            og("⚠️ PDP 登入開始 API 回應錯誤，狀態碼：", response.status_code)
            log("PDP 回應內容：", response.text)
            try:
                err_json = response.json()
                err_msg = err_json.get("error", str(err_json))
            except Exception:
                err_msg = response.text
            return jsonify(error="❌ PDP 錯誤：" + err_msg), 502

    except requests.RequestException as e:
        log(f"❌ 無法連線 PDP：{str(e)}")
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
        log("🔗 正在連接 PDP 登入完成 API...")
        response = requests.post(
            PDP+"login-end",  # <== 改成 PDP API
            json={
                "username": username,
                "credential": credential,
                "source": "akitawan.moe",
                "dist": "akitawan.moe"
            },
            timeout=10,
            verify=False
        )
        log("🔗 連接 PDP 登入完成 API 完成，處理回應...")
        if response.status_code == 200:
            result = response.json()
            token = result.get("token")

            if not token:
                log("⚠️ PDP 登入成功但未返回 token")
                return jsonify(error="驗證成功但未收到 token"), 500

            # ✅ 建立回應並寫入 cookie
            log("✅ PDP 登入成功，返回 token")
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
            log("⚠️ PDP 登入完成 API 回應錯誤，狀態碼：", response.status_code)
            log("PDP 回應內容：", response.text)
            try:
                err_json = response.json()
                err_msg = err_json.get("error", str(err_json))
            except Exception:
                err_msg = response.text

            return jsonify(error="❌ PDP 驗證錯誤：" + err_msg), 502

    except requests.RequestException as e:
        log(f"❌ 登入過程連線 PDP 失敗：{str(e)}")
        return jsonify(error=f"登入過程連線 PDP 失敗：{str(e)}"), 503

# 函數：讓 PDP 檢查權限
@app.route("/check_permission", methods=["POST"])
@attach_jwt_if_available
def check_permission():
    log("開始檢查權限")
    # 檢查是否有 JWT Token
    payload = request.jwt_payload
    # 取得目標
    target = request.json.get("target")  
    # 紀錄是誰要到哪裡
    log(f"檢查權限：使用者 {payload.get('sub', '未知')} | 權限:{payload.get('login_level')} |嘗試存取目標 {target}")
    # 呼叫 PDP 檢查權限
    check_result = check_permission_via_pdp(payload, target)
    # 檢查 PDP 回傳結果
    log(f"PDP 檢查結果：{check_result}")
    # ✅ 無論是否 allow，只要 PDP 給了 reJWT，就更新 cookie
    resp_data = {
        "allow": check_result["allow"],
        "target": check_result.get("redirect_url", target),
        "message": check_result.get("message", "")
    }
    resp = make_response(jsonify(resp_data))  # ⬅️ 先用 make_response 包住
    # 如果 PDP 回傳的 reJWT，則更新 cookie
    if check_result.get("reJWT", None):
        log("🔐 接收到 PDP 回傳的新 JWT，更新 cookie")
        resp.set_cookie(
            "pdp_token", check_result["reJWT"],
            max_age=3600,
            httponly=True,
            secure=True,
            samesite="None",
            path="/"
    )

    if not check_result["allow"]:
        return resp, 403
    # 如果 PDP 允許存取，回傳目標網址
    return resp, 200

""" 管理使用者 """
@app.route("/ldap-admin")
@attach_jwt_if_available
def ldap_admin():
    payload = request.jwt_payload
    if not payload:
        log("🚫 沒有附帶 JWT Payload，禁止存取")
        return jsonify({"error": "缺少登入資訊"}), 401
    target = "2=>ldap-admin"

    # 呼叫 PDP 檢查權限
    check_result = check_permission_via_pdp(payload, target)
    log(f"PDP 檢查結果：{check_result}")

    # 若不允許，回傳錯誤頁面
    if not check_result.get("allow", False):
        resp = make_response(jsonify({
            "error": check_result.get("message", "存取被拒")
        }), 403)
        # 有 reJWT 也更新 cookie
        if check_result.get("reJWT"):
            resp.set_cookie(
                "pdp_token", check_result["reJWT"],
                max_age=3600, httponly=True,
                secure=True, samesite="None", path="/"
            )
        return resp

    # ✅ 有權限 → 顯示頁面
    resp = make_response(render_template("ldap_admin.html"))
    if check_result.get("reJWT"):
        log("🔐 接收到 PDP 回傳的新 JWT，更新 cookie")
        resp.set_cookie(
            "pdp_token", check_result["reJWT"],
            max_age=3600, httponly=True,
            secure=True, samesite="None", path="/"
        )
    return resp



""" LDAP API 路由 - 轉發給 PDP 處理實際邏輯 """
@app.route("/ldap-api", methods=["POST"])
def ldap_api():
    PDP_URL = "https://private.inside:8964/PDP/ldap-api"  # ✅ 根據內網實際設定
    try:
        # ⬇️ 接收前端 JSON 請求
        payload = request.get_json()
        log("🔁 將資料轉發給 PDP：", payload)

        # ⬇️ 轉發給 PDP 的 /ldap-api
        response = requests.post(
            PDP_URL,
            json=payload,
            timeout=10,
            verify=False  # 🚨 若使用自簽憑證，請確認安全性需求
        )

        # ⬇️ 回傳 PDP 回應內容給前端
        return jsonify(response.json()), response.status_code

    except requests.RequestException as e:
        log("🚫 無法連線 PDP：", e)
        return jsonify({"error": f"無法連線 PDP：{str(e)}"}), 503

""" 其他路由 """
@app.route("/rick-roll")
@attach_jwt_if_available
def rick_roll():
    payload = request.jwt_payload
    if not payload:
        log("🚫 沒有附帶 JWT Payload")
        return jsonify({"error": "缺少登入資訊"}), 401

    target = "3=>Rick"

    # ⬇️ 向 PDP 查詢權限
    check_result = check_permission_via_pdp(payload, target)
    log(f"PDP 檢查結果：{check_result}")

    if not check_result.get("allow") or int(payload.get("login_level", 0)) < 3:
        resp = make_response(jsonify({
            "error": "無權限存取此頁面"
        }), 403)
        if check_result.get("reJWT"):
            resp.set_cookie(
                "pdp_token", check_result["reJWT"],
                max_age=3600, httponly=True,
                secure=True, samesite="None", path="/"
            )
        return resp

    resp = make_response(render_template("rick_roll.html"))
    if check_result.get("reJWT"):
        resp.set_cookie(
            "pdp_token", check_result["reJWT"],
            max_age=3600, httponly=True,
            secure=True, samesite="None", path="/"
        )
    return resp

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

