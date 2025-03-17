import base64
import os

""" Global Variables """

# 設定 RP 相關資訊
RP_ID = "fido2.akitawan.moe"  # 改成你的正式域名
RP_NAME = "My WebAuthn App"  # 可保持不變，或改成你的應用名稱
ORIGIN = "https://fido2.akitawan.moe"  # 改成你的正式域名，且使用 HTTPS
# 設定常用變數
g_IP = "0.0.0.0"  # Flask 在 Render 上應該綁定所有 IP
g_Port = int(os.environ.get("PORT", 8080))  # Render 會自動分配 PORT
g_SSL_crt = r"SSL_file\\server.crt"  # 這裡的 SSL_crt 要改成你的 SSL 憑證
g_SSL_key = r"SSL_file\\server.key"  # 這裡的 SSL_key 要改成你的 SSL 金鑰

g_secret_key = os.urandom(32)  # secret_key 使用亂數生成


# 在 Cloud Run 上使用 /app/Database/fido2_user.db
if os.getenv("GAE_ENV", ""):  # 代表 GCP Cloud Run 環境
    db_users = "/app/Database/fido2_user.db"
else:  # 本地端使用 SQLite
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
