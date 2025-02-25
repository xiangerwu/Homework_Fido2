# **Fido2 WebAuthn 專案**

這是一個 **使用 Fido2 技術進行 WebAuthn 註冊和認證** 的專案，後端使用 **Flask**，前端透過 **JavaScript** 與 WebAuthn API 交互。  
```
分支說明:
1.main  | 改失敗的分支，之後要合併
2.proxmox | 架設在實驗室的版本，未分離版本，需改 host 
3.localhost | 筆電用的 demo 版本
4.Gpt4-o | 分割路由最新版

```
專案結構
```
├── routes/
│   ├── register.py          # 處理 WebAuthn 註冊流程
│   ├── auth.py              # 處理 WebAuthn 登入驗證
├── templates/
│   ├── index.html           # Web 前端測試頁面
├── static/
│   ├── script.js            # 處理 WebAuthn 前端邏輯
├── app.py                   # Flask 伺服器主程式
├── global_config.py         # 全域變數與系統配置
└── README.md                # 本文件
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

| **路由 (Route)**               | **HTTP 方法** | **描述** |
|-------------------------------|--------------|---------|
| `/`                           | `GET`        | **首頁**，顯示歡迎詞及 WebAuthn 入口 |
| `/main`                       | `GET`        | **主要頁面**，前端 HTML |
| `/register`                   | `POST`       | **註冊 API**，生成 WebAuthn 註冊選項 |
| `/register/store-credential`  | `POST`       | **存儲憑證**，驗證註冊回應並存儲憑證資料 |
| `/auth`                       | `POST`       | **驗證註冊**，生成新 challenge 並更新用戶資料 |
| `/auth/verify-credential`     | `POST`       | **驗證憑證**，驗證 WebAuthn 登入 |
| `/clear`                      | `POST`       | **清除全部用戶資料** |

---
功能說明
1. 註冊 (/register)

    流程：
        用戶提供 username，後端產生 隨機 user_id。
        後端建立 WebAuthn 註冊選項 並回傳至前端。
        前端使用 FIDO2 安全裝置產生公私鑰，並回傳至後端。
        伺服器驗證並儲存公鑰憑證。

    API
        POST /register/ → 產生註冊選項
        POST /register/store-credential → 儲存用戶憑證

2. 登入 (/auth)

    流程：
        用戶提供 username，伺服器回傳 驗證挑戰碼。
        前端透過 FIDO2 安全裝置簽署挑戰碼並傳送至後端驗證。
        伺服器驗證簽名成功後，允許登入。

    API
        POST /auth/ → 產生驗證挑戰碼
        POST /auth/verify-credential → 驗證憑證並完成登入

3. 清除用戶數據 (/clear)

    POST /clear → 清空所有用戶數據
---

## **🔧 其他資訊**

其他說明

    可將 users 轉為 資料庫 儲存
    RP_ID (localhost) 可修改為正式網域
    可擴展支援 U2F (USB Key) 或 TPM (可信模組)
    
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
     192.168.50.222 wzx_test.com

     ```