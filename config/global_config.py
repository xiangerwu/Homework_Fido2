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
RP_ID = "proxy.akitawan.moe"  # Fido2 用到
ORIGIN = "akitawan.moe" # 改成你的正式域名，且使用 HTTPS


# 設定常用變數
db_users = "Database/fido2_user.db"


# 來源與 JWKS URL 對照表
SOURCE_KEY_URLS = {
    "akitawan.moe": "server_key/server.crt",
    "oauth.akitawan.moe": "https://proxy.akitawan.moe/wu/oauth/jwks.json",
    "NCtA-client":"",
    # 可擴充更多來源
}
""" General Functions """

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

# 函數：產生 JWT Token
def generate_jwt(
    username: str,
    aaguid: str = None,
    sign_count: int = None,
    source: str = None,
    destination: str = None,
    role: str = "user",
) -> str:
    """
    產生 JWT Token

    參數:
        username (str): 使用者識別 ID
        aaguid (str): FIDO2 裝置的識別碼（可選）
        sign_count (int): FIDO2 裝置的簽名計數器（可選）
        role (str): 使用者權限（預設為 'user'）
        "source"：來源網站
        "destination"：目的地網站

    回傳:
        str: JWT 字串（已簽章）
    """
    # 取得當前時間
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=10)

    # 產生 JWT  的 payload  
    print("包裝 payload")
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),  # 簽發時間
        "exp": int(exp.timestamp()),  # 到期時間
        "src": source,  # 來源網站
        "aud": destination,  # 目的地網站
        "iss": ORIGIN,  # 發行者
    }
    # 如果有提供 aaguid 和 sign_count，則加入 payload
    if aaguid:
        payload["aaguid"] = aaguid
    if sign_count is not None:
        payload["signCount"] = sign_count

    # 是否加密 payload 取決於 source 是否在對照表中
    if source in SOURCE_KEY_URLS:
        print("將 payload加密")
        recipient_key = load_public_key_by_source(source)
        claims = encrypt_payload_with_jwe(payload,recipient_key)
    else:
        print("不將 payload加密")
        claims = payload  # 不加密
   
    #  
    # 讀取 server_key/server.key
    print("讀取私鑰 A")
    with open("server_key/server.key", "rb") as f:
        private_key = jwk.JWK.from_pem(f.read())
    # 用私鑰簽名 JWT
    print("用私鑰 A 簽章")
    token = jwt.JWT(header={"alg": "RS256", "kid": "A1"}, claims=claims)
    token.make_signed_token(private_key)
    jwt_str = token.serialize(compact=True)
    return jwt_str

# 函數：解碼 JWT Token
# 作用: 驗證 JWT Token 的簽名，並解密 payload
# 參數: JWT Token 字串
# 回傳: payload 字典，或 None 以及錯誤訊息
def decode_jwt(jwt_str: str):
    try:
        with open("server_key/server.crt", "rb") as f:
            public_key = jwk.JWK.from_pem(f.read())
        # Step 3: 解密 payload（使用 A 自己的私鑰）
        with open("server_key/server.key", "rb") as f:
            private_key = jwk.JWK.from_pem(f.read())

        # Step 1: 驗章（用 A 的公鑰）
        print("驗簽 JWT ")
        token = jwt.JWT(jwt=jwt_str, key=public_key)
        # Step 2: 從 token.claims 中讀出 JWE 字串（加密的 payload）
        print("📦 取得加密的 JWE Payload")
        encrypted_jwe_str = token.claims
        jwe_token = jwe.JWE()
        print("解密 payload")
        jwe_token.deserialize(encrypted_jwe_str, key=private_key)

        # Step 4: 解析 payload 為 JSON
        payload = json.loads(jwe_token.payload.decode("utf-8"))
        print("✅ 解密完成，Payload:", payload)

        # Step 5: 驗證發行者
        if payload.get("iss") != ORIGIN:
            raise ValueError("無效的發行者")

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
        token = request.cookies.get("token")
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
            print("JWT Token 有效",payload)
        if jwt_error:
            print("JWT Token 無效",jwt_error)
        return f(*args, **kwargs)
    return wrapper    