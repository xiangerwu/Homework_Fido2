
# Fido2 WebAuthn 專案

## 專案結構

```
.
├── .gitignore
├── .vscode/
│   └── launch.json
├── app.py
├── config
    ├── global_config.py
│   └── db_manager.py  
├── requirement.txt
├── routes/
│   ├── auth.py
│   └── register.py
├── SSL_file/
│   ├── rootCA.crt
│   ├── rootCA.key
│   ├── server.crt
│   └── server.key
├── static/
│   ├── script.js
│   └── web_functions.js
└── templates/
    └── index.html

```

## 環境設置

1. 安裝所需套件：
    ```sh
    pip install -r requirement.txt
    ```

2. 設置 `.vscode/launch.json` 以便在 Visual Studio Code 中進行偵錯。

3. 資料庫採用 SQLite ，之後再補

## 專案說明

### 主要檔案

- `app.py`：主應用程式入口，設置 Flask 應用並引入路由。
- `global_config.py`：全域變數與通用函式。
- `db_manager.py` ：控制資料庫
- `requirement`：所需的 Python 套件列表。

### 路由

- `routes/register.py`：處理 WebAuthn 註冊的路由。
- `routes/auth.py`：處理 WebAuthn 憑證驗證的路由。

### 靜態檔案

- `static/script.js`：前端 JavaScript 檔案，處理 WebAuthn 註冊和登入功能。
- `static/web_functions.js`：前端 JavaScript 工具函式。

### 模板

- `templates/index.html`：主頁面模板。

### SSL 憑證

- `SSL_file/`：存放 SSL 憑證和金鑰的目錄。

## 使用說明

1. 啟動應用程式：
    ```sh
    python app.py
    ```

2. 在瀏覽器中打開 `https://localhost:5000` 進行測試。
