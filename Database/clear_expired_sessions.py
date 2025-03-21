# clear_expired_sessions.py

import time
from config.global_config import db_users
from db_manager import DatabaseManager

def clear_expired_sessions():
    try:
        with DatabaseManager(db_users) as db:
            db.clear_expired_sessions(expiry_seconds=43200)  # 12 小時
        print("[OK] Expired sessions cleared.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    clear_expired_sessions()

# 輸入以下指令來編輯 crontab：
# crontab -e
# 在底部新增這一行（假設你的專案在 /home/ubuntu/fido2-app/）：
# 0 */12 * * * /usr/bin/python3 /home/wzx/Homework_Fido2/Database/clear_expired_sessions.py >> /home/ubuntu/fido2-app/Database/session_cleanup.log 2>&1
