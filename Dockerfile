FROM python:3.11-slim

# 設定工作目錄
WORKDIR /app

# 複製專案內的所有檔案到容器內
COPY . .

# 升級 pip 版本
RUN pip install --upgrade pip

# 安裝所有相依套件（從 requirements.txt）
RUN pip install -r requirements.txt

# 確保資料庫目錄存在（SQLite 資料庫存放在 /app/Database/）
RUN mkdir -p /app/Database

# 設定 Cloud Run 預設的 PORT
ENV PORT=8080

# 暴露 Cloud Run 使用的 port
EXPOSE 8080

# 指定運行 Flask 服務
CMD ["python", "app.py"]
