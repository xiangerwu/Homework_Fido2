import base64

# 模擬用戶資料庫（未來可更換為真正的資料庫）
users = {}

# 設定 RP 相關資訊
RP_ID = "localhost"
RP_NAME = "My WebAuthn App"
ORIGIN = "https://localhost:5000"
# 設定常用變數
g_IP = "127.0.0.1"
g_Port = 5000
g_SSL_crt = "../SSL_file/server.crt"
g_SSL_key = "../SSL_file/server.key"
g_secret_key = ""


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
