import base64
import os
import html, re
import jwt
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from flask import request



""" Global Variables """


g_IP = "0.0.0.0"  # Flask 在 Render 上應該綁定所有 IP
# g_IP = "127.0.0.1"
RP_NAME = "My WebAuthn App"  # 可保持不變，或改成你的應用名稱
g_secret_key = os.urandom(32)  # secret_key 使用亂數生成
g_port = 5000  # 預設 Flask 埠號

# 設定 RP 相關資訊
RP_ID = "fido2-web.akitawan.moe"  # 改成你的正式域名
ORIGIN = "https://fido2-web.akitawan.moe"  # 改成你的正式域名，且使用 HTTPS
# 設定常用變數
db_users = "Database/fido2_user.db"


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


# 函數：將 username 轉換為 HTML 實體編碼
def sanitize_username(username):
    return html.escape(username)


# 函數：將 HTML 實體編碼轉換回正常字符
def unsanitize_username(safe_username):
    return html.unescape(safe_username)


# 函數：產生 JWT Token
def generate_jwt(
    username: str,
    aaguid: str = None,
    sign_count: int = None,
    role: str = "user",
    expire_minutes: int = 60,
) -> str:
    """
    產生 JWT Token

    參數:
        username (str): 使用者識別 ID
        aaguid (str): FIDO2 裝置的識別碼（可選）
        sign_count (int): FIDO2 裝置的簽名計數器（可選）
        role (str): 使用者權限（預設為 'user'）
        expire_minutes (int): Token 有效時間（分鐘）

    回傳:
        str: JWT 字串（已簽章）
    """
    # 取得當前時間
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=60)

    # 產生 JWT Token 的 payload  
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),  # 簽發時間
        "exp": int(exp.timestamp()),  # 到期時間
        "iss": ORIGIN,  # 發行者
    }

    if aaguid:
        payload["aaguid"] = aaguid
    if sign_count is not None:
        payload["signCount"] = sign_count

    token = jwt.encode(payload, g_secret_key, algorithm="HS256")
    return token

# 函數：檢查 JWT Token 是否有效
def decode_jwt(token: str):
    """
    解碼 JWT Token

    參數:
        token (str): JWT 字串（已簽章）

    回傳:
        dict: 解碼後的 payload
        str: 錯誤訊息（如果有的話）
    """
    try:
        payload = jwt.decode(token, g_secret_key, algorithms=["HS256"],issuer=ORIGIN)
        return payload,None # 解碼成功，回傳 Payload 字典
    except jwt.ExpiredSignatureError:
        return None, str("Token 已過期")
    except jwt.InvalidTokenError :
        return None, str("無效的 Token") 
    except jwt.InvalidSignatureError:
        return None, str("無效的簽名")
    except jwt.DecodeError:
        return None, str("解碼錯誤")
    except jwt.InvalidIssuerError:
        return None, str("無效的發行者")
    except Exception as e:
        return None, str(f"其他錯誤: {e}")
        
    
# 函數：檢查 JWT Token 是否存在
def attach_jwt_if_available(f):
    @wraps(f) # 確保原始函數的元資料不會被覆蓋
    # @wraps(f) 是一個裝飾器，用來保留原始函數的元資料
    # (例如函數名稱、文檔字串等)，這樣在調試或使用函數時，可以獲得正確的資訊。
    # 當你使用裝飾器來包裝一個函數時，
    # 原始函數的名稱、文檔字串等資訊不會被改變。
    def wrapper(*args, **kwargs): 
        # 從請求的 cookies 中獲取 JWT Token        
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

        return f(*args, **kwargs)
    return wrapper    