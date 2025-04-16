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
# 模擬儲存授權碼（可改為 Redis）
AUTH_CODE_STORE = {}



# 網頁路徑 /oauth2/authorize
# 作用: OAuth 認證頁面
@oauth_bp.route("/authorize", methods=["GET"])
@attach_jwt_if_available
def authorize():
    print(" 收到 /authorize 請求")
    print(" Cookies:", request.cookies)

    # ✅ Step 1: 擷取來自 B 的參數
    received_client_id      = request.args.get("client_id")
    received_redirect_uri   = request.args.get("redirect_uri")
    received_response_type  = request.args.get("response_type")
    received_scope          = request.args.get("scope", "")
    received_state          = request.args.get("state")
    received_username       = request.args.get("username",None)

    # ✅ Step 2: 檢查參數完整性
    if not all([received_client_id, received_redirect_uri, received_response_type, received_state]):
        missing_params = "❌ [authorize] 缺少必要參數："
        if not received_client_id:
            missing_params += "client_id "
        if not received_redirect_uri:
            missing_params += "redirect_uri "
        if not received_response_type:
            missing_params += "response_type "
        if not received_state:
            missing_params += "state "
        return missing_params, 400

    if received_response_type != "code":
        return "❌ [authorize] 不支援的 response_type", 400

    # ✅ Step 3: 檢查是否登入
    # 判斷 username 參數
    # 如果有 username 參數，則表示使用者確定要登入的帳號
    
    if (not request.jwt_payload) | (received_username == None):
        print("❎ 尚未登入 → 顯示登入頁")
        # 傳遞參數回登入頁面以便後續 redirect 回來
        return render_template(
            "oauth_login.html",
            client_id=received_client_id,
            redirect_uri=received_redirect_uri,
            scope=received_scope,
            state=received_state,
            response_type = received_response_type
        )
   
    

    # ✅ Step 4: 使用者已登入，產生授權碼
    user_id = request.jwt_payload["sub"]
    role = request.jwt_payload["role"]
    sign_count = request.jwt_payload.get("signCount", 0)
    aaguid = request.jwt_payload.get("aaguid", None)
    code = str(uuid4())

    # ✅ Step 5: 儲存授權碼資料
    AUTH_CODE_STORE[code] = {
        "user_id": user_id,
        "role": role,
        "sign_count": sign_count,
        "aaguid": aaguid,
        "client_id": received_client_id,
        "redirect_uri": received_redirect_uri,
        "scope": received_scope,
        "issued_at": int(time.time()),
        "expires_in": 300  # 5 分鐘有效
    }

    print(f"✅ 使用者 {user_id} 已登入，授權碼產生：{code}")

    # ✅ Step 6: 回傳授權碼 via postMessage
    return render_template("auth_success.html", code=code, state=received_state,status="login_success")


# 網頁路徑 /oauth2/Code2Token
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
    print("收到參數")
    # ✅ Step 1: 檢查參數
    if not all([received_code, received_client_id, received_redirect_uri, received_grant_type]):
        return jsonify({"error": "缺少必要參數"}), 400
    if received_grant_type != "authorization_code":
        return jsonify({"error": "不支援的 grant_type"}), 400
    print("參數檢查完成")
    # ✅ Step 2: 驗證授權碼是否存在
    code_data = AUTH_CODE_STORE.get(received_code)
    if not code_data:
        return jsonify({"error": "無效的授權碼"}), 400
    
    # 將 URL 解碼，避免出現 %20 等編碼問題
    Saved_redirect_Url= urllib.parse.unquote(code_data["redirect_uri"])
    received_redirect_uri= urllib.parse.unquote(received_redirect_uri)
    print("Saved_redirect_Url   :",Saved_redirect_Url)
    print("received_redirect_uri:",received_redirect_uri)
    print("client_id         :",code_data["client_id"])
    print("received_client_id:",received_client_id)
    
    # ✅ Step 3: 驗證 client_id 與 redirect_uri 是否一致
    print("驗證 client_id 與 redirect_uri 是否一致")
    if code_data["client_id"] != received_client_id:
        return jsonify({"error": "client_id "}), 400
    print("client_id 驗證完成")
    if Saved_redirect_Url != received_redirect_uri:
        return jsonify({"error": "redirect_uri 不一致"}), 400
    print("client_id 與 redirect_uri 驗證完成")

    # ✅ Step 4: 檢查是否過期（預設 5 分鐘有效）
    now = datetime.now(timezone.utc)
    print("now:", now)
    issued_time = datetime.fromtimestamp(code_data["issued_at"], timezone.utc)
    print("issued_time:", issued_time)
    if now - issued_time > timedelta(minutes=5):
        return jsonify({"error": "授權碼已過期"}), 400
    print("授權碼未過期")
    # ✅ Step 5: 簽發 id_token（JWT）
    id_token = generate_jwt(
        username=code_data["user_id"],
        aaguid=code_data["aaguid"],
        sign_count=code_data["sign_count"],
        role=code_data["role"],
        expire_minutes=1
    )
    print("id_token:", id_token)

    # ✅ Step 6: 清除一次性 code（只可使用一次）
    del AUTH_CODE_STORE[received_code]
    print("已清除授權碼：", received_code)
    # ✅ Step 7: 回傳 id_token
    return jsonify({
        "access_token": id_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    })

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
