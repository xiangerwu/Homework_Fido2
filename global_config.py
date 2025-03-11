import base64
import os

""" Global Variables """
# 模擬用戶資料庫（未來可更換為真正的資料庫）
users = {}

# 設定 RP 相關資訊
RP_ID = "localhost"  # 這裡的 RP_ID 要改成你的網站域名
RP_NAME = "My WebAuthn App"  # 這裡的 RP_NAME 要改成你的網站名稱
ORIGIN = "https://localhost:5000"  # 這裡的 ORIGIN 要改成你的網站域名
# 設定常用變數
g_IP = "127.0.0.1"  # 這裡的 IP 要改成你的 IP
g_Port = 5000  # 這裡的 Port 要改成你的 Port
g_SSL_crt = "SSL_file\server.crt"  # 這裡的 SSL_crt 要改成你的 SSL 憑證
g_SSL_key = "SSL_file\server.key"  # 這裡的 SSL_key 要改成你的 SSL 金鑰

g_secret_key = os.urandom(32)  # secret_key 使用亂數生成


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


# 函式名稱: chek_username
# 作用: 檢查使用者資料，分別帶入 data 與
# 類型參數
# register          :1
# store_credential  :2
# verify_credential :3
# verify_register   :4
def chek_username(type, data):
    # 錯誤訊息
    error = ""

    # 如果沒有數據，回傳錯誤
    if not data:
        return ["請提供有效的 JSON 數據", False]

    # 取得用戶名稱與憑證資料
    username = data.get("username")
    credential_data = data.get("credential")

    # 設定錯誤條件
    if type in [2, 3, 4] and username not in users:
        error = "用戶不存在"
    elif type == 1 and not username:
        error = "請提供 username"
    elif type == 1 and username in users:
        error = "用戶已存在"
    elif type in [2, 4] and not credential_data:
        error = "請提供 credential"
    elif type == 3 and "credential" not in users.get(username, {}):
        error = "註冊資料不存在"

    # 依照類型回傳不同資料
    if error:
        return [error, False]

    return (
        [error, username, credential_data]
        if type in [2, 4]
        else [error, username] if type == 1 else [error, users[username]["credential"]]
    )
