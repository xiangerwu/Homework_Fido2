# 使用 Python 3.11 輕量版作為基底映像檔
FROM python:3.11-slim

# 設定工作目錄
WORKDIR /app

# 複製專案內的所有檔案到容器內
COPY . .

# 升級 pip 版本
RUN pip install --upgrade pip

# 安裝所有相依套件（從 requirements.txt）
RUN pip install -r requirements.txt

# 設定 Cloud Run 預設的 PORT（確保 Flask 正確綁定）
ENV PORT=8080

# 暴露 Cloud Run 使用的 port
EXPOSE 8080

# 指定運行 Flask 服務
CMD ["python", "app.py"]
