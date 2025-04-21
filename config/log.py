# 這個用來寫 log 到本地或是資料庫
# 應該分成 紀錄的通用函式
# 然後再用參數決定 紀錄到資料庫或本地檔案
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime

# 設定 log 檔案名稱
log_file = "app.log"
# 設定 log 檔案路徑
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
# 確保 log 目錄存在
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
# 設定 log 檔案完整路徑
log_path = os.path.join(log_dir, log_file)
# 設定 log 檔案大小限制
max_bytes = 10 * 1024 * 1024  # 10 MB
# 設定 log 檔案保留數量
backup_count = 5
# 設定 log 等級
log_level = logging.DEBUG
# 設定 log 格式
log_format = "%(asctime)s - %(levelname)s - %(message)s"
# 設定 log 時區
log_timezone = "Asia/Taipei"
# 設定 log 時區
class CustomFormatter(logging.Formatter):
    def converter(self, timestamp):
        # 將時間轉換為指定時區
        dt = datetime.fromtimestamp(timestamp)
        return dt.astimezone(timezone.utc).astimezone(tz=log_timezone)
    def format(self, record):
        # 設定 log 時區
        record.asctime = self.formatTime(record, self.datefmt)
        return super().format(record)

# 整理成 class
class logger:
    def __init__(self, log_file="app.log", log_dir=None, max_bytes=10*1024*1024, backup_count=5, log_level=logging.DEBUG, log_format="%(asctime)s - %(levelname)s - %(message)s", log_timezone="Asia/Taipei"):
        self.log_file = log_file
        self.log_dir = log_dir if log_dir else os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.log_level = log_level
        self.log_format = log_format
        self.log_timezone = log_timezone
        self.logger = None
        self.setup_logger()
        self.setup_file_handler()
        self.setup_console_handler()
        self.setup_db_handler()
        self.setup_other_handler()
        self.setup_handlers()
    def setup_logger(self):
        # 設定 log 根目錄
        self.logger = logging.getLogger()
        self.logger.setLevel(self.log_level)
    def setup_file_handler(self):
        # 設定 log 檔案名稱
        log_path = os.path.join(self.log_dir, self.log_file)
        # 設定 log 檔案處理器
        file_handler = RotatingFileHandler(log_path, maxBytes=self.max_bytes, backupCount=self.backup_count)
        file_handler.setLevel(self.log_level)
        # 設定 log 格式
        formatter = CustomFormatter(self.log_format)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    def setup_console_handler(self):
        # 設定 log 輸出到控制台
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(CustomFormatter(self.log_format))
        self.logger.addHandler(console_handler)
    def setup_db_handler(self):
        # 設定 log 輸出到資料庫
        # db_handler = DBHandler()
        # db_handler.setLevel(self.log_level)
        # db_handler.setFormatter(CustomFormatter(self.log_format))
        # self.logger.addHandler(db_handler)
        pass
    def setup_other_handler(self):
        # 設定 log 輸出到其他地方
        # other_handler = OtherHandler()
        # other_handler.setLevel(self.log_level)
        # other_handler.setFormatter(CustomFormatter(self.log_format))
        # self.logger.addHandler(other_handler)
        pass
    def setup_handlers(self):
        # 設定 log 檔案處理器
        self.logger.addHandler(self.file_handler)
        # 設定 log 輸出到控制台
        self.logger.addHandler(self.console_handler)
        # 設定 log 輸出到資料庫
        # self.logger.addHandler(self.db_handler)
        # 設定 log 輸出到其他地方
        # self.logger.addHandler(self.other_handler)
        pass
    def log(self, level, message):
        # 設定 log 等級
        if level == "debug":
            self.logger.debug(message)
        elif level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
        elif level == "critical":
            self.logger.critical(message)
        else:
            self.logger.info(message)
    def debug(self, message):
        self.log("debug", message)
    def info(self, message):
        self.log("info", message)
    def warning(self, message):
        self.log("warning", message)
    def error(self, message):
        self.log("error", message)
    def critical(self, message):
        self.log("critical", message)
    def exception(self, message):
        self.log("error", message)
        self.logger.exception(message)
    def fatal(self, message):
        self.log("critical", message)
        self.logger.fatal(message)
    def get_logger(self):
        return self.logger
    def get_log_file(self):
        return self.log_file
    def get_log_dir(self):
        return self.log_dir
    def get_max_bytes(self):
        return self.max_bytes
    def get_backup_count(self):
        return self.backup_count
    def get_log_level(self):
        return self.log_level
    def get_log_format(self):
        return self.log_format
    def get_log_timezone(self):
        return self.log_timezone
    def get_log_path(self):
        return os.path.join(self.log_dir, self.log_file)
    def get_log_handlers(self): 
        return self.logger.handlers
    def get_log_handler(self, handler):
        return self.logger.getHandler(handler)
  