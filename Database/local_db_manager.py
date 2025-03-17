import sqlite3


def update_database(db_file):
    try:
        # 連接到 SQLite 資料庫
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # 刪除現有的 Users_List 表
        cursor.execute("DROP TABLE IF EXISTS Users_List")

        # 創建 Users_List 表，並增加 session 欄位
        cursor.execute(
            """
            CREATE TABLE Users_List (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                User_name TEXT NOT NULL,
                Credential BLOB,
                RegisteredAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # 刪除現有的 Users_Log 表
        cursor.execute("DROP TABLE IF EXISTS Users_Log")

        # 創建 Users_Log 表
        cursor.execute(
            """
            CREATE TABLE Users_Log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                User_name TEXT NOT NULL,
                authenticator TEXT,
                IP TEXT,
                OS TEXT,
                Device TEXT,
                browser TEXT,
                login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                login_status INTEGER
            )
        """
        )

        # 刪除現有的 Users_Session 表
        cursor.execute("DROP TABLE IF EXISTS Users_Session")
        # 創建 Users_Session 表，User_name 不重複
        cursor.execute(
            """
            CREATE TABLE Users_Session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                User_name TEXT NOT NULL UNIQUE,
                Session BLOB
            )
        """
        )

        # 提交更改並關閉連接
        conn.commit()
        conn.close()
        print("Database updated successfully!")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # 呼叫函數更新資料庫
    update_database("fido2_user.db")
