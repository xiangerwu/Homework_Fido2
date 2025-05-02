"""
說明
oauth2 模塊
作用： 
- 提供 OAuth2 認證流程
- 包含授權碼交換為 Token 的 API
- 提供 JWKS 端點以供客戶端驗證 JWT

- /oauth2/authorize: OAuth 認證頁面
    - 當用戶未登入時，顯示登入頁面
    - 當用戶已登入時，產生授權碼並回傳給客戶端

- /oauth2/Code2Token: 授權碼轉換為 Token
    - 驗證授權碼的有效性
    - 驗證 client_id 與 redirect_uri 是否一致
    - 驗證授權碼是否過期
    - 簽發 id_token（JWT）

- /.well-known/jwks.json: 公開 JWT 金鑰
    - 提供 JWKS 端點以供客戶端驗證 JWT
"""

""" Import Module """
# 引入 flask 模塊
from flask import Blueprint, request, jsonify, session, render_template,redirect
import urllib.parse
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time
# 引入 global_config 自定義模塊
from config.global_config import (
    RP_ID,
    RP_NAME,
    ORIGIN,
    base64url_uint,
    attach_jwt_if_available,
    generate_jwt,
    decode_jwt,
)

# import app as app_server
from app import server as app_server


""" Create Blueprint """
# 創建 Blueprint
oauth_bp = Blueprint("oauth", __name__)

""" OAuth Functions """
# 網頁路徑 /oauth2/authorize
# 作用: OAuth 認證頁面
@oauth_bp.route("/authorize", methods=["GET"])
@attach_jwt_if_available
def authorize():
    print(" 收到 /authorize 請求")
    print(" Cookies:", request.cookies)

    # ✅ Step 1: 擷取來自 B 的參數
    received_source         = request.args.get("source")
    received_distination    = request.args.get("dist")
    received_redirect_uri   = request.args.get("redirect_uri")
    received_response_type  = request.args.get("response_type")
    received_scope          = request.args.get("scope", "")
    received_state          = request.args.get("state")
    received_username       = request.args.get("username",None)

    # ✅ Step 2: 檢查參數完整性
    required_params = {
        "source"        : received_source,
        "dist"          : received_distination,
        "redirect_uri"  : received_redirect_uri,
        "response_type" : received_response_type,
        "state"         : received_state,
    }

    missing = [name for name, val in required_params.items() if not val]
    if missing:
        return f"❌ [authorize] 缺少必要參數：{' '.join(missing)}", 400

    if received_response_type != "JWT":
        return "❌ [authorize] 不支援的 response_type", 400

    # ✅ Step 3: 檢查是否登入
    # 判斷 username 參數
    # 如果有 username 參數，則表示使用者確定要登入的帳號
    
    if (not request.jwt_payload) | (received_username == None):
        print("❎ 尚未登入 → 顯示登入頁")
        # 傳遞參數回登入頁面以便後續 redirect 回來
        return render_template(
            "oauth_login.html",        
            received_source=received_source,
            received_distination=received_distination,
            redirect_uri=received_redirect_uri,
            scope=received_scope,
            state=received_state,
            response_type = received_response_type
        )
   
    # ✅ Step 4: 使用者已登入，直接導向回 B 的 redirect_uri
    print("✅ 使用者已登入，直接跳轉回 redirect_uri")
    # return redirect(received_redirect_uri)
    return render_template("auth_success.html",state=received_state,status="login_success")

# 網頁路徑 /oauth2/.well-known/jwks.json
# 作用: 公開 JWT 金鑰
@oauth_bp.route("/.well-known/jwks.json")
def jwks():
    with open("server_key/server.crt", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        public_key = cert.public_key()

    # 轉成 JWKS 格式（略簡化版）
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": base64url_uint(numbers.n),
        "e": base64url_uint(numbers.e),
        "kid": "A1",  # 可自行定義金鑰 ID
    }

    return jsonify({"keys": [jwk]})
