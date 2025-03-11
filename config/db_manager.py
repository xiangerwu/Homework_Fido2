# 這個檔案是用來連接資料庫的，
# 注意是否是在程式中執行，
# 如果是，則引入global_config.py中的db_users變數
# 否則，引入config.global_config.py中的db_users變數
if __name__ == "__main__":
    from global_config import db_users
else:
    from config.global_config import db_users

import sqlite3


# Connect to the database
def connect_to_db(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        # print(f"Connected to {db_file}")
    except sqlite3.Error as e:
        print(f"Error connect to database:{e}")

    return conn


def insert_user_into_db(conn, query, values):
    try:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        # print("Data inserted successfully")
        return True
    except sqlite3.Error as e:
        print(f"Error inserting user into database: {e}")
        return False


def query_db_user(conn, username):
    try:
        cur = conn.cursor()
        # 查詢 Users 表中的資料
        query = "SELECT * FROM Users WHERE User_name = ?;"
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        if not user:
            return None
        else:
            return user[2]
    except sqlite3.Error as e:
        print(f"Error querying user data : {e}")
        return None


def query_db_credential(conn, username):
    try:
        cur = conn.cursor()
        # 查詢 Credential 表中的資料
        query = "SELECT * FROM Credential WHERE User_name = ?;"
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        if not user:
            return None
        else:
            return user[2]
    except sqlite3.Error as e:
        print(f"Error querying credential: {e}")
        return None


def update_user_credential(conn, values):
    try:
        # 更新 Users 表中的 Credential 欄位
        query = "UPDATE Credential SET Credential = ? WHERE User_name = ?"
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        # print("Data updated successfully")
        return True
    except sqlite3.Error as e:
        print(f"Error updating credential: {e}")
        return False


def close_db(conn):
    if conn:
        conn.close()
        # print("Connection closed")
    return None


def delete_all_db(conn):

    # 清空Users表
    clear_users_table = "DELETE FROM Users;"
    # 清空Credential表
    clear_credential_table = "DELETE FROM Credential;"
    for i in [clear_users_table, clear_credential_table]:
        conn.execute(i)
        conn.commit()
    return "Database cleared"


# 設計一個通用函式，依照 參數呼叫不同的DB操作
# 這個函式是用來執行資料庫操作的，包含 connet_to_db, query_db, insert_into_db, update_db, close_db
def db_operation(db_file, operation, query, values=None):
    conn = connect_to_db(db_file)
    if operation == "query_user":
        result = query_db_user(conn, values)
    elif operation == "query_credential":
        result = query_db_credential(conn, values)
    elif operation == "insert":
        result = insert_user_into_db(conn, query, values)
    elif operation == "update":
        result = update_user_credential(conn, values)
    elif operation == "delete":
        result = delete_all_db(conn)
    else:
        result = "Invalid operation"
    close_db(conn)
    return result


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
    client_credential_data = data.get("credential")

    # 資料庫查詢
    db_user = db_operation(db_users, "query_user", None, username)
    db_credential = db_operation(db_users, "query_credential", None, username)
    # 設定錯誤條件
    if type == 1 and not username:
        error = "請提供 username"
    elif type in [2, 3, 4] and not db_user:
        error = "用戶不存在"
    elif type == 1 and db_user:
        error = "用戶已存在"
    elif type in [2, 4] and not client_credential_data:
        error = "請提供 credential"
    elif type == 3 and not db_credential:
        error = "註冊資料不存在"

    # 依照類型回傳不同資料
    if error:
        return [error, False]

    return (
        [error, username, client_credential_data]
        if type in [2, 4]
        else [error, username] if type == 1 else [error, db_credential]
    )


# Test the database connection
if __name__ == "__main__":

    conn = connect_to_db(db_users)
    close_db(conn)
