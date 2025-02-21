# **Fido2 WebAuthn 專案**

這是一個 **使用 Fido2 技術進行 WebAuthn 註冊和認證** 的專案，後端使用 **Flask**，前端透過 **JavaScript** 與 WebAuthn API 交互。  

## **📂 目錄結構**
```
Fido2/ 
├── python/ 
│ ├── app.py # Flask 後端 API 
│ ├── static/ 
│ │ └── script.js # WebAuthn 前端邏輯 
│ └─ templates/ 
│   └── index.html # 前端 HTML
│
├── SSL_file/ #金鑰相關檔案
└──
```
### **🖥️ 伺服器運行**
本專案運行於：  
👉 **`https://wzx_test.com:5000`**

### **🚀 註冊 & 認證**
1. **打開瀏覽器**：前往 `https://wzx_test.com:5000/main`
2. **註冊 ID**：
   - 輸入使用者名稱
   - 點擊 **「註冊 ID」** 按鈕
3. **認證 (登入)**：
   - 使用相同的使用者名稱
   - 點擊 **「用 ID 登入」** 按鈕

---

## **📜 主要 API 端點**
本專案的 Flask 伺服器 (`app.py`) 提供以下 API 端點：

| **路由 (Route)**        | **HTTP 方法** | **描述** |
|------------------------|--------------|---------|
| `/`                    | `GET`        | **首頁**，顯示歡迎詞及 WebAuthn 入口 |
| `/main`                | `GET`        | **主要頁面**，前端 HTML |
| `/register`            | `POST`       | **註冊 API**，生成 WebAuthn 註冊選項 |
| `/store-credential`    | `POST`       | **存儲憑證**，驗證註冊回應並存儲憑證資料 |
| `/verify-register`     | `POST`       | **驗證註冊**，生成新 challenge 並更新用戶資料 |
| `/verify-credential`   | `POST`       | **驗證憑證**，驗證 WebAuthn 登入 |
| `/clear`               | `POST`       | **清除全部用戶資料** |

---

## **📌 主要功能說明**
### **🔹 `register()` - 產生註冊選項**
- 取得用戶名稱，產生 **隨機用戶 ID (`os.urandom(16)`)**
- 使用 `generate_registration_options()` 產生 WebAuthn 註冊選項
- 儲存 `challenge` 到 `session`
- 回傳 **JSON 格式的 WebAuthn 註冊資訊**

### **🔹 `store_credential()` - 存儲 WebAuthn 憑證**
- 解析並驗證 **`clientDataJSON`**
- 執行 `verify_registration_response()` 驗證 WebAuthn 註冊資料
- **存儲公鑰 (`publicKey`) 與憑證 (`credential.id`)** 供日後登入驗證

### **🔹 `verify_register()` - 產生挑戰碼 (Challenge)**
- 生成新的 `challenge`
- 將其儲存到 `session`，更新 `users[username]`
- **Base64 編碼** 確保 JSON 可序列化
- 回傳 **WebAuthn 認證挑戰資訊**

### **🔹 `verify_credential()` - WebAuthn 驗證**
- 取得用戶憑證 (`publicKey`) 與 **signCount**
- 使用 `verify_authentication_response()` 驗證用戶身份
- **更新 signCount，確保防重放攻擊 (Replay Attack)**

### **🔹 `clear()` - 清除所有用戶資料**
- 清空 `users` 字典，移除所有儲存的憑證與挑戰碼

---

## **📜 前端 API (JavaScript)**
### **📁 `/static/script.js`**
**WebAuthn 主要前端邏輯**

| **函式 (Function)**         | **用途** |
|----------------------------|---------|
| `base64UrlToUint8Array()`  | **Base64 解碼**，用於解析憑證 |
| `uint8ArrayToBase64Url()`  | **Base64 編碼**，存儲憑證 |
| `arrayBufferToBase64()`    | **ArrayBuffer 轉 Base64** |
| `showMessage()`            | 顯示 UI 訊息 |
| `sendRequest()`            | 發送 HTTP 請求 |
| `register()`               | 用戶 WebAuthn 註冊 |
| `verify_register()`        | 用戶 WebAuthn 認證 |
| `clearData()`              | 清除憑證資訊 |

---

## **🔧 其他資訊**
### **⚙️ 安裝與運行**
1. 安裝 **Python 依賴**

```python
pip install -r requirement.txt
```
2. 生成 SSL 憑證 (自簽)

3. 運行 Flask 伺服器
```
python app.py
```

🌍 相關技術

    Python Flask - 後端 API
    WebAuthn API - FIDO2 身份驗證
    JavaScript Fetch API - 與後端交互
    Base64 編碼 - 儲存 bytes 型態資料



    使用系統管理員修改
     C:\WINDOWS\system32\drivers\etc\hosts 
     加入 
     
     ```
     127.0.0.1 wzx_test.com

     ```