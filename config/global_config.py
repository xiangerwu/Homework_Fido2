import base64
import os

""" Global Variables """

# 設定 RP 相關資訊
RP_ID = "localhost"  # 這裡的 RP_ID 要改成你的網站域名
RP_NAME = "My WebAuthn App"  # 這裡的 RP_NAME 要改成你的網站名稱
ORIGIN = "https://localhost:5000"  # 這裡的 ORIGIN 要改成你的網站域名
# 設定常用變數
g_IP = "127.0.0.1"  # 這裡的 IP 要改成你的 IP
g_Port = 5000  # 這裡的 Port 要改成你的 Port
g_SSL_crt = r"SSL_file\\server.crt"  # 這裡的 SSL_crt 要改成你的 SSL 憑證
g_SSL_key = r"SSL_file\\server.key"  # 這裡的 SSL_key 要改成你的 SSL 金鑰

g_secret_key = os.urandom(32)  # secret_key 使用亂數生成


# SQLite Database file
db_users = r"D:\\Project\\Database\\SQLite\\fido2_user.db"


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
