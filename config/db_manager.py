# 這個檔案是用來連接資料庫的
# 包含了連接資料庫的函式，以及對資料庫進行操作的函式
from config.global_config import db_users
import sqlite3


# 如何 import 這個 class
# from config.db_manager import DatabaseManager
# 如何呼叫 class
# with DatabaseManager(db_users) as db:
# 解釋一下這個 clas 的作用
# 這個 class 有幾個方法
# 1. get_user_name(username) 用來查詢用戶，回傳用戶名稱與用戶 ID
# 2. get_credential(username) 用來查詢憑證，回傳用戶名稱與憑證
# 3. insert_user(username, Credential) 用來新增用戶，無回傳
# 4. update_credential(username, credential) 用來更新憑證，無回傳
# 5. log_user_login(username, authenticator, ip, os, device, browser) 用來記錄用戶登入，無回傳
# 6. delete_user(username) 用來刪除用戶，無回傳
# 7. delete_all() 用來刪除所有資料，無回傳



# 意思是使用 db_users 這個資料庫檔案來連接資料庫
class DatabaseManager:
    # 初始化設定資料庫檔案
    def __init__(self, db_file):
        self.db_file = db_file

    # 連接資料庫
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_file)
        return self

    # 關閉資料庫
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    #  通用函式
    def execute_query(
        self, query, params=(), fetchone=False, fetchall=False, commit=False
    ):
        try:
            cursor = self.conn.cursor()  # 建立游標
            cursor.execute(query, params)  # 執行SQL語句
            # 如果 commit 為 True，則提交事務
            if commit:
                self.conn.commit()
                return None
            # 如果 fetchone 為 True，則返回一條記錄
            if fetchone:
                return cursor.fetchone()
            # 如果 fetchall 為 True，則返回所有記錄
            if fetchall:
                return cursor.fetchall()
            return None
        # 如果發生錯誤，則返回錯誤訊息
        except sqlite3.Error as e:
            print(f"Error executing query: {e}")
            raise Exception(f"Error executing query: {e}")

    # 查詢用戶，回傳用戶名稱與用戶 ID
    def get_user_name(self, username):
        try:
            query = "SELECT User_name FROM Users_List WHERE User_name = ?;"
            return self.execute_query(query, (username,), fetchone=True)
        except Exception as e:
            raise Exception(f"Error getting user: {e}")

    # 查詢憑證，回傳用戶名稱與憑證
    def get_credential(self, username):
        try:
            query = "SELECT Credential FROM Users_List WHERE User_name = ?;"
            return self.execute_query(query, (username,), fetchone=True)
        except Exception as e:
            raise Exception(f"Error getting credential: {e}")

    # 新增用戶，無回傳
    def insert_user(self, username, Credential):
        try:
            query = "INSERT INTO Users_List (User_name, Credential) VALUES (?, ?);"
            return self.execute_query(query, (username, Credential), commit=True)
        except Exception as e:
            raise Exception(f"Error inserting user: {e}")

    # 更新憑證，無回傳
    def update_credential(self, username, credential):
        try:
            query = "UPDATE Users_List  SET Credential = ? WHERE User_name = ?;"
            return self.execute_query(query, (credential, username), commit=True)
        except Exception as e:
            raise Exception(f"Error updating credential: {e}")

    def log_user_login(self,username, authenticator, ip, os, device, browser):
        try:
            query = "INSERT INTO Users_Log (User_name, authenticator, IP, OS, Device, browser, login_time) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', 'localtime'));"
            return self.execute_query(query, (username, authenticator, ip, os, device, browser), commit=True)
        except Exception as e:
            raise Exception(f"Error logging user login: {e}")

    def delete_user(self, username):
        try:
            query = "DELETE FROM Users_List WHERE User_name = ?;"  # 刪除用戶
            return self.execute_query(query, (username,), commit=True)
        except Exception as e:
            raise Exception(f"Error deleting user: {e}")

    # 刪除所有資料，無回傳
    def delete_all(self):
        try:
            clear_Users_List = "DELETE FROM Users_List;"
            clear_Users_Log = "DELETE FROM Users_Log;"
            for i in [clear_Users_Log, clear_Users_List]:
                self.execute_query(i, commit=True)
            return "Database cleared"
        except Exception as e:
            raise Exception(f"Error deleting all data: {e}")


# Test the database connection
if __name__ == "__main__":

    with DatabaseManager(db_users) as db:
        conn = db.conn
