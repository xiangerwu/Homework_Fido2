"""說明
# oauth 模塊
# 作用： 


"""

""" Import Module """

# 引入 flask 模塊
from flask import Blueprint, request, jsonify, session, render_template,redirect
import os, json
import secrets
from uuid import uuid4
from datetime import datetime, timedelta, timezone
import time
# 引入 global_config 自定義模塊
from config.global_config import (
    RP_ID,
    RP_NAME,
    ORIGIN,
    base64url_to_bytes,
    encode_bytes_to_base64,
    db_users,
    sanitize_username,
    unsanitize_username,
    attach_jwt_if_available,
    generate_jwt,
    decode_jwt,
)

# 引入 db_manager 自定義模塊
from Database.db_manager import DatabaseManager


# import app as app_server
from app import server as app_server

""" Create Blueprint """
# 創建 Blueprint
oauth_bp = Blueprint("oauth", __name__)


""" OAuth Functions """
# 模擬儲存授權碼（可改為 Redis）
AUTH_CODE_STORE = {}

# 網頁路徑 /oauth/authorize
# 作用: OAuth 認證頁面
@oauth_bp.route("/authorize", methods=["GET"])
@attach_jwt_if_available
def authorize():
    print("🧠 收到 /authorize 請求")
    print("🔎 Cookies:", request.cookies)

    # ✅ Step 1: 擷取來自 B 的參數
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    response_type = request.args.get("response_type")
    scope = request.args.get("scope", "")
    state = request.args.get("state")

    # ✅ Step 2: 檢查參數完整性
    if not all([client_id, redirect_uri, response_type, state]):
        return "❌ 缺少必要參數", 400

    if response_type != "code":
        return "❌ 不支援的 response_type", 400

    # ✅ Step 3: 檢查是否登入
    if not request.jwt_payload:
        print("❎ 尚未登入 → 顯示登入頁")
        # 傳遞參數回登入頁面以便後續 redirect 回來
        return render_template(
            "oauth_login.html",
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
        )

    # ✅ Step 4: 使用者已登入，產生授權碼
    user_id = request.jwt_payload["sub"]
    code = str(uuid4())

    # ✅ Step 5: 儲存授權碼資料
    AUTH_CODE_STORE[code] = {
        "user_id": user_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "issued_at": int(time.time()),
        "expires_in": 300  # 5 分鐘有效
    }

    print(f"✅ 使用者 {user_id} 已登入，授權碼產生：{code}")

    # ✅ Step 6: 回傳授權碼 via postMessage
    return render_template("auth_success.html", code=code, state=state)


# 網頁路徑 /oauth/Code2Token
# 作用: 將授權碼轉換為 Token
# 是後端 API，應該不會直接被用戶端調用
@oauth_bp.route("/Code2Token", methods=["POST"])
def code_to_token():
    print("收到 /Code2Token 請求")
    # 獲取請求的 JSON 資料
    received_data = request.json or {}
    # 獲取參數
    received_code           = received_data.get("code")
    received_client_id      = received_data.get("client_id")
    received_redirect_uri   = received_data.get("redirect_uri")
    received_grant_type     = received_data.get("grant_type")

    # ✅ Step 1: 檢查參數
    if not all([received_code, received_client_id, received_redirect_uri, received_grant_type]):
        return jsonify({"error": "缺少必要參數"}), 400
    if received_grant_type != "authorization_code":
        return jsonify({"error": "不支援的 grant_type"}), 400

    # ✅ Step 2: 驗證授權碼是否存在
    code_data = AUTH_CODE_STORE.get(received_code)
    if not code_data:
        return jsonify({"error": "無效的授權碼"}), 400

    # ✅ Step 3: 驗證 client_id 與 redirect_uri 是否一致
    if code_data["client_id"] != received_client_id or code_data["redirect_uri"] != received_redirect_uri:
        return jsonify({"error": "client_id 或 redirect_uri 不一致"}), 400

    # ✅ Step 4: 檢查是否過期（預設 5 分鐘有效）
    now = datetime.now(timezone.utc)
    issued_time = datetime.fromtimestamp(code_data["issued_at"], timezone.utc)
    if now - issued_time > timedelta(minutes=5):
        return jsonify({"error": "授權碼已過期"}), 400

    # ✅ Step 5: 簽發 id_token（JWT）
    id_token = generate_jwt(
        username="auth_server",
        role="thired_party",
        expire_minutes=60
    )

    # ✅ Step 6: 清除一次性 code（只可使用一次）
    del AUTH_CODE_STORE[received_code]

    return jsonify({
        "access_token": id_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    })