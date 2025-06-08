from config.global_config import *
from config.ldap_manager import LDAP_ManagerControl
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
# sslify = SSLify(app)

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
    log(f"🔍 來源 IP: {source_ip}")
    return True  # 暫時允許所有來源，後續可強化檢查


# 登入決策
# 除非有路由不然一律 404
@app.route("/", methods=["GET", "POST"])
def index():
    # 404 Not Found
    return jsonify({"error": "Not Found"}), 404

""" 註冊路由-開始 """
@app.route("/register-begin", methods=["POST"])
def register_begin():
    log("🔍 收到註冊請求")
    if not verify_source():
        log("🚫 來源不被允許")
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    log(f"🔍 用戶名稱: {username}")
    if not username:
        return jsonify({"error": "缺少用戶名稱"}), 400

    # ✅ 查詢使用者是否存在於 LDAP
    result, status = LDAP_ManagerControl("search", username=username)
    if status == 200:
        log(f"🚫 使用者 {username} 已存在於 LDAP")
        return jsonify({"error": "使用者已存在 LDAP"}), 400
    log(f"🔍 使用者 {username} 不存在，開始 Fido2 註冊流程")

   # ✅ 使用 Fido2 的統一處理函式
    return connect_pip_fido2(
        endpoint="register",
        payload={"username": username}
    )
    


""" 註冊路由-結束 """
@app.route("/register-end", methods=["POST"])
def register_end():
    log("🔍 收到註冊完成請求")
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403
    data = request.get_json()
    username = data.get("username")
    if not username:
        log("🚫 缺少 username")
        return jsonify({"error": "缺少 username"}), 400

    data = request.get_json()
    log(f"🔍 收到註冊資料: {data}")
    # ✅ 呼叫 FIDO2 儲存憑證
    result, error = connect_pip_fido2(
        endpoint="register/store-credential",
        payload=data,
        raw_mode=True  # ← 改成 raw_mode，拿資料不直接回傳
    )
    log(f"🔍 FIDO2 註冊結果: {result}, 錯誤: {error}")
    if error:
        log(f"🚫 註冊失敗: {error}")
        return jsonify({"error": error}), 502

    # 準備寫入 LDAP
    username = data.get("username")
    if not username:
        log("🚫 FIDO2 回傳成功，但缺少 username")
        return jsonify({"error": "FIDO2 回傳成功，但缺少 username"}), 400
    log(f"➕ 新增 LDAP 使用者: {username}")
    result, status = LDAP_ManagerControl("create", username=username)
    if status != 200:
     return jsonify({"error": f"FIDO2 成功，但 LDAP 建立失敗: {result.get('message', '')}"}), 500

    log("✅ 註冊流程完成，FIDO2 與 LDAP 都成功")
    return jsonify({"status": "ok", "message": "FIDO2 註冊成功，LDAP 建立成功"}), 200

    
""" 登入路由-開始 """
@app.route("/login-begin", methods=["POST"])
def login_begin():
    log("🔍 收到登入請求")
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    log(f"🔍 用戶名稱: {username}")
    if not username:
        return jsonify({"error": "缺少用戶名稱"}), 400

     # ✅ 使用封裝後的函式
    return connect_pip_fido2(
        endpoint="authentication/verify-username",
        payload={"username": username}
    )

""" 登入路由-結束 """
@app.route("/login-end", methods=["POST"])
def login_end():
    log("🔍 收到登入完成請求")
    
    if not verify_source():
        return jsonify({"error": "來源不被允許"}), 403

    data = request.get_json()
    username = data.get("username")
    credential = data.get("credential")
    log(f"🔍 用戶名稱: {username}, 憑證資料: {credential}")
    
    if not username or not credential:
        return jsonify({"error": "請提供用戶名稱與憑證資料"}), 400

    # ✅ 取得 FIDO2 發回的 JWT
    fido2_result, err = connect_pip_fido2(
        endpoint="authentication/verify-credential",
        payload={"username": username, "credential": credential},
        include_source_dist=True,
        expect_token=True,
        raw_mode=True  # 不直接回傳 response，取出資料自己處理
    )
    # 如果有錯誤，回傳錯誤訊息
    if err:
        return jsonify({"error": err}), 502
    
    # 如果沒有 token，回傳錯誤訊息
    if not fido2_result:
        log("🚫 FIDO2 回應中缺少 token")
        return jsonify({"error": "FIDO2 回應中缺少 token"}), 500

    # 將 fido2_result 轉換成 PDP token
    log("🔍 開始處理 PDP token")
    result, err = issue_pdp_token_from_fido2_jwt(fido2_result)
    # 如果有錯誤，回傳錯誤訊息
    if err:
        log(f"🚫 處理 PDP token 時發生錯誤: {err}")
        return jsonify({"error": err}), 401
    # 如果成功，回傳 PDP token
    log(f"🔍 處理 PDP token 成功: {result}\n")
    return jsonify(result), 200


""" 權限檢查路由 """
@app.route("/authz-check", methods=["POST"])
def authz_check():
    log("🔍 收到授權檢查請求")
    data = request.get_json(silent=True) or {}
    log(f"🔍 收到授權檢查資料: {data}")

    payload = data.get("payload")
    target = data.get("target")

    # ✅ 檢查 payload 和 target 是否存在
    if not payload or not target:
        log("🚫 缺少 payload 或 target")
        return make_authz_response(False, "缺少 payload 或 target", status=400)


    # ✅ 提取使用者資訊
    user_name = payload.get("sub")
    if not user_name:
        log("🚫 JWT 缺少使用者資訊 (sub)")
        return make_authz_response(False, "JWT 缺少使用者資訊 (sub)", status=400)
    log(f"🔍 使用者登入名稱: {user_name}")

    # ✅ 解析 target 格式 "1=>WuOAuth"
    log(f"🔍 處理 target: {target}")
    try:
        required_level, target_name = target.split("=>")
        required_level = int(required_level)
        log(f"🔍 需求權限等級: {required_level}，目標名稱: {target_name}")
    except ValueError:
        log("🚫 target 格式錯誤")
        return make_authz_response(False, "target 格式錯誤", status=400)


    # ✅ 載入權限資料
    permissions = load_permissions()

    # ✅ 查詢 LDAP 權限
    result, status = LDAP_ManagerControl("search", username=user_name)
    if status != 200:
        return make_authz_response(False, f"查詢 LDAP 權限失敗：{result['message']}", status=403)
    now_level = int(result["level"])
    log(f"🔐 使用者 {user_name} 的當前等級為: {now_level}")

    # ✅ 若 payload 權限與 LDAP 權限不一致 ➜ 應重新簽發 JWT
    payload_level = int(payload.get("login_level", 0))
    if int(payload_level) != int(now_level):
        log("⚠️ 使用者 payload 權限與 LDAP 不一致，需重新簽發 JWT")
        new_payload = payload.copy()
        new_payload["login_level"] = now_level
        new_token = generate_jwt(new_payload, now_level)
        return make_authz_response(False, "授權通過，但權限已更新", rejwt=new_token)


    # ✅ 權限不足（需求等級比實際等級高）
    if int(now_level) < int(required_level):
        log("🚫 權限不足")
        return make_authz_response(False, f"目前權限等級為 {now_level}，不足以訪問等級 {required_level} 的資源", status=403)


    # ✅ 授權清單中尋找目標名稱對應的實際網址
    matched_link = None
    for level in range(1, now_level + 1):  # 權限大的可訪問低等級資源
        level_key = str(level)
        if not isinstance(permissions, dict):
            log("🚫 權限設定載入錯誤")
            return make_authz_response(False, "系統權限設定錯誤", status=500)
        # 檢查當前等級的權限是否存在
        for item in permissions.get(level_key, []):
            if item.get("name") == target_name:
                matched_link = item.get("link")
                log(f"✅ 成功匹配目標連結：{matched_link}")
                break
        if matched_link:
            break

    if not matched_link:
        log("🚫 未找到指定的目標")
        return make_authz_response(False, f"未找到符合名稱 {target_name} 的目標", status=404)
    if matched_link is None:
        log("🚫 系統錯誤：目標連結遺失")
        return make_authz_response(False, "系統錯誤：目標連結遺失", status=500)

    # ✅ 最終授權通過
    return make_authz_response(True, "授權通過", redirect_url=matched_link)


""" LDAP API 路由 """
@app.route("/ldap-api", methods=["POST"])
def ldap_api():
    log("🔍 收到 LDAP API 請求")
    data = request.get_json()
    result, status = LDAP_ManagerControl(
        action=data.get("action"),
        username=data.get("username"),
        level=data.get("level")
    )
    log(f"🔍 LDAP API 請求結果: {result}, 狀態碼: {status}")
    return jsonify(result), status

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
