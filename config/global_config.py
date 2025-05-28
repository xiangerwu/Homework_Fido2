import base64
import os
import html, re
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request
import requests
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import urlsafe_b64encode,urlsafe_b64decode
from jwcrypto import jwk,jwe,jws,jwt
from jwcrypto.common import JWException

""" Global Variables """


g_IP = "0.0.0.0"  # Flask 在 Render 上應該綁定所有 IP
RP_NAME = "My WebAuthn App"  # 可保持不變，或改成你的應用名稱
g_secret_key = os.urandom(32)  # secret_key 使用亂數生成
g_port = 5000  # 預設 Flask 埠號

# 設定 RP 相關資訊
# RP_ID = "fido2-web.akitawan.moe"  # 改成你的正式域名
# 代理用
RP_ID = "akitawan.moe"  # Fido2 用到
ORIGIN = "akitawan.moe" # 改成你的正式域名，且使用 HTTPS


SOURCE_KEY_URLS = {
    "fido2": "192.168.50.222:5000/oauth2/jwks.json",  # FIDO2 的 JWKS URL
}

""" General Functions """

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

# 函數：將 username 轉換為 HTML 實體編碼
def sanitize_username(username):
    return html.escape(username)

# 函數：將 HTML 實體編碼轉換回正常字符
def unsanitize_username(safe_username):
    return html.unescape(safe_username)

# 函數: 取得對應來源的公鑰
# 作用: 取得來源的 JWKS URL，並從中獲取公鑰
def load_public_key_by_source(source: str) -> jwk.JWK:
    # 檢查來源是否在對照表中
    url_or_path = SOURCE_KEY_URLS[source]
    print(f"取得來源 {source} 的公鑰: {url_or_path}")
    # 如果來源是 URL，則從 URL 下載公鑰
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        res = requests.get(url_or_path)
        res.raise_for_status()
        return jwk.JWK(**res.json()["keys"][0])
    # 如果來源是本地檔案，則從檔案讀取公鑰
    else:
        print(f"從本地檔案讀取公鑰: {url_or_path}")
        with open(url_or_path, "rb") as f: 
            return jwk.JWK.from_pem(f.read())
        
# 函數：解碼 JWT Token
# 作用: 驗證 JWT Token 的簽名，並解密 payload
# 參數: JWT Token 字串
# 回傳: payload 字典，或 None 以及錯誤訊息
# 入口網站只驗簽
def decode_jwt(jwt_str: str):
    try:
        public_key = load_public_key_by_source("fido2")
        # private_key = load_public_key_by_source("fido2")  # 假設私鑰與公鑰相同，實際應用中應分開
        # Step 1: 驗章（用 A 的公鑰）
        print("驗簽 JWT ")
        token = jwt.JWT(jwt=jwt_str, key=public_key)
        # Step 2: 從 token.claims 中讀出 JWE 字串（加密的 payload）
        # print("📦 取得加密的 JWE Payload")
        # encrypted_jwe_str = token.claims
        # jwe_token = jwe.JWE()
        # 先不解密
        print("解密 payload(暫不解密只驗簽)")
        # jwe_token.deserialize(encrypted_jwe_str, key=private_key)
        # Step 4: 解析 payload 為 JSON
        # payload = json.loads(jwe_token.payload.decode("utf-8"))
        payload = "未解密的 payload，可簽發 JWT"
        print("✅ 解密完成，Payload:", payload)

        # Step 5: 驗證發行者
        # if payload.get("iss") != ORIGIN:
            # raise ValueError("無效的發行者")

        return payload, None

    except jwt.JWTExpired as e:
        return None, f"❌ JWT 過期: {str(e)}"
    except jwt.JWTInvalidClaimFormat as e:
        return None, f"❌ Claim 格式錯誤: {str(e)}"
    except jwk.JWException as e:
        return None, f"❌ 金鑰錯誤: {str(e)}"
    except Exception as e:
        return None, f"❌ 其他錯誤: {e}"
    

# 函數：檢查 JWT Token 是否存在
def attach_jwt_if_available(f):
    @wraps(f) # 確保原始函數的元資料不會被覆蓋
    # @wraps(f) 是一個裝飾器，用來保留原始函數的元資料
    # (例如函數名稱、文檔字串等)，這樣在調試或使用函數時，可以獲得正確的資訊。
    # 當你使用裝飾器來包裝一個函數時，
    # 原始函數的名稱、文檔字串等資訊不會被改變。
    def wrapper(*args, **kwargs): 
        # 從請求的 cookies 中獲取 JWT Token        
        print("開始檢查TOKEN")
        token = request.cookies.get("pdp_token")
        print(f"取得的 JWT Token: {token}")
        # 嘗試解碼 JWT Token
        # 如果 token 不存在，payload 會是 None
        # 如果 token 存在但無效，payload 會是 None
        # 如果 token 存在且有效，payload 會是字典
        # 只驗簽不解密，payload 會是固定字串
        payload ,jwt_error= decode_jwt(token) if token else (None,None) 
        
        # 若有合法 JWT 就會變成 dict，否則是 None
        request.jwt_payload = payload 
        # 如果有錯誤，則會是錯誤訊息
        request.jwt_error = jwt_error 
        if payload:
            print("JWT Token 有效",payload)
        if jwt_error:
            print("JWT Token 無效",jwt_error)
        return f(*args, **kwargs)
    return wrapper    