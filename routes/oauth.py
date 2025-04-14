"""說明
# oauth 模塊
# 作用： 


"""

""" Import Module """

# 引入 flask 模塊
from flask import Blueprint, request, jsonify, session, render_template,redirect
import os, json
import secrets
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
)

# 引入 db_manager 自定義模塊
from Database.db_manager import DatabaseManager


# import app as app_server
from app import server as app_server

""" Create Blueprint """
# 創建 Blueprint
oauth_bp = Blueprint("oauth", __name__)


""" OAuth Functions """

#  暫存 code 對應資料（可用 Redis 替換）
code_cache = {}  # 格式: { code: { user, client_id, redirect_uri, exp } }

# 產生授權碼
# 1. 產生安全亂數授權碼
# 2. 儲存對應資料到暫存（這裡簡單用 dict，可換 Redis）
# 3. 返回授權碼
# 4. 授權碼有效時間預設 60 秒
def generate_auth_code(user_id, client_id, redirect_uri, expire_seconds=60):
    # 產生安全亂數授權碼
    code = secrets.token_urlsafe(16)

    # 儲存對應資料到暫存（這裡簡單用 dict，可換 Redis）
    code_cache[code] = {
        "user_id": user_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "exp": time.time() + expire_seconds
    }
    return code

# 驗證授權碼
# 1. 檢查授權碼是否存在
# 2. 檢查授權碼是否過期
# 3. 檢查 client_id 與 redirect_uri 是否符合原本發出的
# 4. 檢查授權碼是否已被使用
# 5. 驗證成功後，刪除授權碼
# 6. 驗證失敗，返回錯誤訊息
def validate_and_consume_code(code, client_id, redirect_uri):
    # 檢查授權碼是否存在
    info = code_cache.get(code)
    if not info:
        return None, "授權碼不存在或已使用"

    # 時間過期
    if time.time() > info["exp"]:
        del code_cache[code]
        return None, "授權碼已過期"

    # 驗證 client_id 與 redirect_uri 是否符合原本發出的
    if info["client_id"] != client_id or info["redirect_uri"] != redirect_uri:
        return None, "授權碼與 client_id 或 redirect_uri 不符"

    # 一次性使用 → 刪除
    del code_cache[code]
    return info, None

# 網頁路徑 /oauth/authorize
# 作用: OAuth 認證頁面
@oauth_bp.route("/authorize", methods=["GET"])
@attach_jwt_if_available
def authorize():
    # 檢查用戶是否已登入
    if not request.jwt_payload:
        # 如果未登入，重定向到登入頁面
        return render_template("oauth_login.html") 
    # 如果已登入，顯示授權頁面
    # 取得前端傳來的必要參數
    user_id = request.jwt_payload["sub"]
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    # 產生授權碼
    code = generate_auth_code(user_id, client_id, redirect_uri)
    # 將授權碼回傳給前端
    # 這裡使用 GET 方法回傳，實際上可以使用 POST 方法
    return redirect(f"{redirect_uri}?code={code}&state={state}")





# 網頁路徑 /oauth/token
# 作用: OAuth Token 發放頁面
@oauth_bp.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")

    info, error = validate_and_consume_code(code, client_id, redirect_uri)
    if error:
        return jsonify({"error": error}), 400

    # 產生 access_token
    token = generate_jwt(username=info["user_id"], role="user", expire_minutes=60)

    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600
    })
