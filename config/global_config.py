import base64
import os
import html, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, make_response, render_template
from flask import Flask, redirect, url_for, session, flash
import requests
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import urlsafe_b64encode,urlsafe_b64decode
from jwcrypto import jwk,jwe,jws,jwt
from jwcrypto.common import JWException
from config.ldap_manager import  LDAP_ManagerControl
""" Global Variables """


g_IP = "0.0.0.0"  # Flask 在 Render 上應該綁定所有 IP
RP_NAME = "My WebAuthn App"  # 可保持不變，或改成你的應用名稱
g_secret_key = os.urandom(32)  # secret_key 使用亂數生成
g_port = 1919  # 預設 Flask 埠號

# 設定 RP 相關資訊
# RP_ID = "fido2-web.akitawan.moe"  # 改成你的正式域名
# 代理用
RP_ID = "akitawan.moe"  # Fido2 用到
ORIGIN = "akitawan.moe" # 改成你的正式域名，且使用 HTTPS

# PIP 端點
PIPS = {
    "Fido2": "https://private.inside:8964/Fido2/",
    "OAuth": "https://oauth.akitawan.moe/",
}
# 來源與 JWKS URL 對照表
SOURCE_KEY_URLS = {
    "akitawan.moe": "server_key/server.crt",
    "oauth.akitawan.moe": "https://proxy.akitawan.moe/wu/oauth/jwks.json",
    "NCtA-client":"",
    "akitawan.moe/en/":"https://proxy.akitawan.moe/en/1/jwks.json",
    # 可擴充更多來源
}

# 預載 permission 對照表
PERMISSION_FILE = Path("config/permission.json")


""" General Functions """

#  函式：記錄訊息
def log(*args):
    now = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(now, *args)

# 函式名稱：載入權限表
def load_permissions():
    try:
        with PERMISSION_FILE.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"[權限載入失敗] {e}")
        return {}

# 函式名稱: encode_bytes_to_base64
# 作用: 遞歸將 bytes 類型轉換為 Base64 字串，確保 JSON 序列化
# 參數: JSON
def encode_bytes_to_base64(data):
    if isinstance(data, bytes):
        return base64.b64encode(data).decode("utf-8")
    elif isinstance(data, dict):
        return {key: encode_bytes_to_base64(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [encode_bytes_to_base64(item) for item in data]
    return data


# 函式名稱: decode_base64_to_bytes
# 作用: 遞迴將 Base64 字串轉換為 bytes 類型，確保 JSON 反序列化
# 參數: JSON
def base64url_to_bytes(base64url_str):
    """將 base64url 字串轉換成 bytes"""
    padding = "=" * (4 - len(base64url_str) % 4)
    return base64.urlsafe_b64decode(base64url_str + padding)

# 函式名稱: base64url_uint
# 作用: 將整數轉換為 Base64URL 編碼的字串（無符號）
# 參數: 整數
def base64url_uint(val: int) -> str:
    """
    將整數轉換為 Base64URL 編碼的字串（無符號）
    - 去掉 '=' padding
    - 使用 URL-safe base64 編碼
    """
    byte_length = (val.bit_length() + 7) // 8
    byte_array = val.to_bytes(byte_length, 'big')  # 轉成 byte
    b64 = base64.urlsafe_b64encode(byte_array).rstrip(b"=")  # URL-safe + 無填充
    return b64.decode("utf-8")

# 函式：將 username 轉換為 HTML 實體編碼
def sanitize_username(username):
    return html.escape(username)

# 函式：將 HTML 實體編碼轉換回正常字符
def unsanitize_username(safe_username):
    return html.unescape(safe_username)

# 函式: 取得對應來源的公鑰
# 作用: 取得來源的 JWKS URL，並從中獲取公鑰
def load_public_key_by_source(source: str) -> jwk.JWK:
    # 檢查來源是否在對照表中
    url_or_path = SOURCE_KEY_URLS[source]
    log(f"取得來源 {source} 的公鑰: {url_or_path}")
    # 如果來源是 URL，則從 URL 下載公鑰
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        res = requests.get(url_or_path)
        res.raise_for_status()
        return jwk.JWK(**res.json()["keys"][0])
    # 如果來源是本地檔案，則從檔案讀取公鑰
    else:
        log(f"從本地檔案讀取公鑰: {url_or_path}")
        with open(url_or_path, "rb") as f: 
            return jwk.JWK.from_pem(f.read())

# 使用 JWE 標準加密 payload 
def encrypt_payload_with_jwe(payload: dict, recipient_key: jwk.JWK) -> str:
    """
    使用 JWE（RSA-OAEP + A256GCM）加密 payload，支援長內容。

    參數:
        payload (dict): 要加密的資料
        recipient_key (jwk.JWK): 對方的公鑰 (JWK 格式)

    回傳:
        str: JWE 字串（Compact Serialization）
    """
    # 將 payload 轉為 JSON 並編碼為 UTF-8 bytes
    plaintext = json.dumps(payload).encode("utf-8")

    # 建立 JWE 加密物件
    jwetoken = jwe.JWE(
        plaintext=plaintext,
        protected={"alg": "RSA-OAEP", "enc": "A256GCM"}
    )
    # 加入收件人（即用 recipient_key 對稱金鑰加密）
    jwetoken.add_recipient(recipient_key)

    # 回傳 Compact 格式（str）
    return jwetoken.serialize(compact=True)

# 函式：生成 JWT Token
def generate_jwt(payload: dict, login_level: int) -> str:
    # 確保 payload 中有必要的欄位
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=10)
    username = payload.get("sub")
    source = payload.get("src")
    destination = payload.get("aud")
    role = payload.get("role", "user")  
    aaguid = payload.get("aaguid")
    sign_count = payload.get("signCount", 0)

    if not username:
        raise ValueError("JWT payload 中缺少 sub 欄位")

    # 組合 payload
    payload = {
        "sub": username,
        "src": source,  # 來源網站
        "aud": destination,  # 目的地網站
        "role": role,        
        "iat": int(now.timestamp()),  # 簽發時間
        "exp": int(exp.timestamp()),  # 到期時間
        "iss": ORIGIN,  # 發行者
        "login_level": login_level, # 登入等級
    }

    # 如果有提供 aaguid 和 sign_count，則加入 payload
    if aaguid:
        payload["aaguid"] = aaguid
    if sign_count:
        payload["signCount"] = sign_count

    # 加密 payload（視來源）
    if source in SOURCE_KEY_URLS:
        log(">> 將 payload 加密")
        recipient_key = load_public_key_by_source(source)
        claims = encrypt_payload_with_jwe(payload, recipient_key)
    else:
        log(">> 不將 payload 加密")
        claims = payload

    # 簽章
    log("讀取私鑰 A")
    with open("server_key/server.key", "rb") as f:
        private_key = jwk.JWK.from_pem(f.read())
    log("用私鑰 A 簽章")
    token = jwt.JWT(header={"alg": "RS256", "kid": "A1"}, claims=claims)
    token.make_signed_token(private_key)

    return token.serialize(compact=True)


# 函式：解碼 JWT Token
# 作用: 驗證 JWT Token 的簽名，並解密 payload
# 參數: JWT Token 字串
# 回傳: payload 字典，或 None 以及錯誤訊息
def decode_jwt(jwt_str: str) -> tuple:
    try:
        with open("server_key/server.crt", "rb") as f:
            public_key = jwk.JWK.from_pem(f.read())
        # Step 3: 解密 payload（使用 A 自己的私鑰）
        # with open("server_key/server.key", "rb") as f:
            # private_key = jwk.JWK.from_pem(f.read())

        # Step 1: 驗章（用 A 的公鑰）
        log("驗簽 JWT ")
        token = jwt.JWT(jwt=jwt_str, key=public_key)
        # Step 2: 從 token.claims 中讀出 JWE 字串（加密的 payload）
        # log("📦 取得加密的 JWE Payload")
        # encrypted_jwe_str = token.claims
        # jwe_token = jwe.JWE()
        log("📦 取得 payload（明文）")
        raw_payload = token.claims
        if not raw_payload:
            raise ValueError("❌ JWT claims 為空，無法解析")

        try:
            payload = json.loads(token.claims)  # ✅ 直接解析明文 JSON payload
        except json.JSONDecodeError as e:
            raise ValueError(f"❌ 無法解析 payload：{e}")
        # jwe_token.deserialize(encrypted_jwe_str)
        # Step 4: 解析 payload 為 JSON
        log("login 不用解密 payload")
        # payload = json.loads(jwe_token.payload.decode("utf-8"))
        log("Payload:", payload)

        # Step 5: 驗證發行者
        if payload.get("iss") != ORIGIN:
            raise ValueError("無效的發行者")
        # 回傳 payload
        return payload, None

    except jwt.JWTExpired as e:
        return None, f"❌ JWT 過期: {str(e)}"
    except jwt.JWTInvalidClaimFormat as e:
        return None, f"❌ Claim 格式錯誤: {str(e)}"
    except jwk.JWException as e:
        return None, f"❌ 金鑰錯誤: {str(e)}"
    except Exception as e:
        return None, f"❌ 其他錯誤: {e}"
    

# 函式：檢查 JWT Token 是否存在
def attach_jwt_if_available(f):
    @wraps(f) # 確保原始函式的元資料不會被覆蓋
    # @wraps(f) 是一個裝飾器，用來保留原始函式的元資料
    # (例如函式名稱、文檔字串等)，這樣在調試或使用函式時，可以獲得正確的資訊。
    # 當你使用裝飾器來包裝一個函式時，
    # 原始函式的名稱、文檔字串等資訊不會被改變。
    def wrapper(*args, **kwargs): 
        # 從請求的 cookies 中獲取 JWT Token        
        log("開始檢查TOKEN")
        token = request.cookies.get("fido2_token")
        # 嘗試解碼 JWT Token
        # 如果 token 不存在，payload 會是 None
        # 如果 token 存在但無效，payload 會是 None
        # 如果 token 存在且有效，payload 會是字典
        payload ,jwt_error= decode_jwt(token) if token else (None,None) 
        
        # 若有合法 JWT 就會變成 dict，否則是 None
        request.jwt_payload = payload 
        # 如果有錯誤，則會是錯誤訊息
        request.jwt_error = jwt_error 
        if payload:
            log("JWT Token 有效",payload)
        if jwt_error:
            log("JWT Token 無效",jwt_error)
        return f(*args, **kwargs)
    return wrapper    


# 函式：連接 PIP FIDO2 伺服器
def connect_pip_fido2(
    endpoint: str,
    payload: dict,
    include_source_dist: bool = False,
    expect_token: bool = False,
    raw_mode: bool = False
):
    """
    向 FIDO2 發送 POST 請求並處理回應

    回傳：
        raw_mode=False（預設）→ 回傳 Flask response 或錯誤 response
        raw_mode=True → 成功: (資料, None)，失敗: (None, 錯誤訊息)
    """
    try:
        post_url = PIPS["Fido2"] + endpoint
        if include_source_dist:
            payload["source"] = "card.example.com"
            payload["dist"] = "fido2.example.com"

        log(f"🔗 向 FIDO2 發送 POST 至 {post_url}，資料：{payload}")
        res = requests.post(post_url, json=payload, timeout=10, verify=False)
        log("📥 回應狀態碼：", res.status_code)

        if res.status_code != 200:
            error_msg = f"FIDO2 驗證失敗（{res.status_code}）：{res.text}"
            log("🚫", error_msg)
            if raw_mode:
                return None, error_msg
            return jsonify({"error": "FIDO2 驗證失敗", "details": res.text}), 502

        # ✅ 回應成功，處理內容
        result = res.json()
        token = result.get("token")

        if expect_token:
            if not token:
                log("🚫 成功但缺少 token")
                if raw_mode:
                    return None, "登入成功但未回傳 token"
                return jsonify({"error": "登入成功但未回傳 token"}), 502

            log(f"🔐 成功取得 Token: {token}")
            if raw_mode:
                return token, None

            resp = make_response(jsonify(result), 200)
            resp.set_cookie("fido2_token", token, max_age=3600, httponly=True)
            log("🍪 已設置 Cookie")
            return resp

        # 非 expect_token 情境
        if raw_mode:
            return result, None
        return jsonify(result), 200

    except requests.RequestException as e:
        error_msg = f"無法連線 FIDO2：{str(e)}"
        log("❌", error_msg)
        if raw_mode:
            return None, error_msg
        return jsonify({"error": error_msg}), 503


# 函式：從 FIDO2 JWT 簽發 PDP 專屬 JWT
def issue_pdp_token_from_fido2_jwt(token: str) -> tuple:
    """
    驗證 FIDO2 回傳的 JWT 並重新簽發 PDP 專屬 JWT。

    參數:
        token (str): FIDO2 回傳的 JWT Token。

    回傳:
        (dict, None) 成功: 包含新 token 的字典
        (None, str) 失敗: 錯誤訊息字串
    """
    # ✅ 驗證 JWT
    log("🔍 開始驗證 FIDO2 回傳的 JWT")
    payload, decode_err = decode_jwt(token)
    if decode_err:
        log(f"🚫 JWT 解碼失敗: {decode_err}")
        return None, decode_err

    username = payload.get("sub")
    if not username:
        log("🚫 JWT 中缺少 sub 欄位")
        return None, "JWT 中缺少 sub 欄位"

    # ✅ 查詢 LDAP 權限
    log(f"🔍 開始查詢 LDAP 權限，使用者: {username}")
    result, status = LDAP_ManagerControl("search", username=username)
    if status != 200:
        log(f"🚫 查詢 LDAP 權限失敗: {result['message']}")
        return None, f"查詢 LDAP 權限失敗：{result['message']}"


    log(f"🔐 使用者 {username} 的登入等級為: {result["level"]}")
    login_level = int(result["level"])  # LDAP 回傳的登入等級
    # ✅ 簽發 PDP 專屬 JWT
    log("🔍 開始簽發 PDP 專屬 JWT")
    new_token = generate_jwt(payload, login_level)
    if not new_token:
        log("🚫 簽發 PDP 專屬 JWT 失敗")
        return None, "簽發 PDP 專屬 JWT 失敗"
    return {
        "status": "ok",
        "message": "成功認證",
        "token": new_token
    }, None

# 函式：生成授權回應
def make_authz_response(allow, message="", redirect_url=None, status=200, rejwt=None):
    response = {
        "allow": allow,
        "message": message,
        "redirect_url": redirect_url,
    }
    if rejwt is not None:
        response["reJWT"] = rejwt
    return jsonify(response), status
