from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
from datetime import datetime, timezone, timedelta


# LDAPManager 類別用於管理 LDAP 使用者，包括搜尋、建立、修改和列出使用者資訊
class LDAPManager:
    # 初始化 LDAP 連線
    def __init__(self):
        ldap_host = "192.168.50.213"
        ldap_port = 389
        ldap_url = f"ldap://{ldap_host}:{ldap_port}"
        ldap_user = "cn=admin,dc=example,dc=org"
        ldap_password = "admin"
        self.base_dn = "cn=employee,ou=employee,dc=example,dc=org"

        server = Server(ldap_url, get_info=ALL)
        self.conn = Connection(
            server, user=ldap_user, password=ldap_password, auto_bind=True
        )

    # 取得使用者條目
    def _get_user_entry(self, username, attributes=None):
        if not username or not isinstance(username, str):
            return None
        try:
            safe_username = escape_filter_chars(username)
            self.conn.search(
                search_base=self.base_dn,
                search_filter=f"(uid={safe_username})",
                search_scope=SUBTREE,
                attributes=attributes or ["*"],
            )
            if self.conn.entries:
                return self.conn.entries[0]
            return None
        except Exception as e:
            print(f"LDAP 查詢錯誤: {e}")
            return None

    # 搜尋使用者權限
    def search(self, username):
        entry = self._get_user_entry(username, attributes=["employeeType"])
        if not entry:
            return False, {"message": "找不到該使用者"}

        if "employeeType" in entry:
            return True, {
                "level": entry.employeeType.value,
                "message": "使用者存在，已取得權限等級",
            }
        else:
            return False, {"message": "沒有 employeeType 權限屬性"}
    
    # 取得下一個可用的 uidNumber
    def get_next_uid_number(self):
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=posixAccount)",
            search_scope=SUBTREE,
            attributes=["uidNumber"],
        )
        uid_numbers = []
        for entry in self.conn.entries:
            try:
                if "uidNumber" in entry:
                    val = int(entry.uidNumber.value)
                    uid_numbers.append(val)
            except (ValueError, TypeError):
                continue

        if uid_numbers:
            return max(uid_numbers) + 1
        return None  # 明確回傳 None 表示抓不到 UID

    # 新增使用者
    def create(self, username):
        if self._get_user_entry(username, attributes=["uid"]):
            return False, {"message": "使用者已存在"}

        next_uid = self.get_next_uid_number()
        if next_uid is None:
            return False, {"message": "無法取得可用的 uidNumber，建立失敗"}

        uid = str(next_uid)
        dn = f"cn={username},{self.base_dn}"
        attrs = {
            "objectClass": ["inetOrgPerson", "posixAccount", "top"],
            "cn": username,
            "sn": username,
            "uid": username,
            "uidNumber": uid,
            "gidNumber": "500",
            "homeDirectory": f"/home/users/{username}",
            "employeeType": "1",
        }

        result = self.conn.add(dn, attributes=attrs)
        if result:
            return True, {"message": f"成功新增使用者（uidNumber={uid}）"}
        else:
            return False, {"message": self.conn.result.get("description", "新增失敗")}

    # 修改使用者權限
    def change(self, username, new_type_value):
        entry = self._get_user_entry(username, attributes=["employeeType"])
        if not entry:
            return False, {"message": f"找不到使用者：{username}"}

        changes = {"employeeType": [(MODIFY_REPLACE, [str(new_type_value)])]}
        result = self.conn.modify(dn=entry.entry_dn, changes=changes)

        if result:
            return True, {"message": f"{username} 的權限已更新為 {new_type_value}"}
        else:
            return False, {"message": self.conn.result.get("description", "修改失敗")}
    
    # 列出所有帳號資訊（uid 與 employeeType）
    def list_all_users(self):
        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter="(objectClass=posixAccount)",
                search_scope=SUBTREE,
                attributes=["uid", "employeeType"],
            )
            result = []
            for entry in self.conn.entries:
                uid = entry.uid.value if "uid" in entry else None
                emp_type = entry.employeeType.value if "employeeType" in entry else None
                if uid:
                    result.append({
                        "username": uid,
                        "employeeType": emp_type or "未設定"
                    })
            return True, result
        except Exception as e:
            return False, {"message": f"LDAP 查詢錯誤: {e}"}


""" 控制 LDAP 使用者管理操作 """
def LDAP_ManagerControl(action, username=None, level=None):
    manager = LDAPManager()
    log(f"🔧 執行 LDAP 操作：{action}，使用者：{username}，等級：{level}")
    if action == "search":
        if not username:
            return {"error": "請提供使用者名稱"}, 400
        ok, result = manager.search(username)
        return result, 200 if ok else 404

    elif action == "create":
        if not username:
            return {"error": "請提供使用者名稱"}, 400
        ok, result = manager.create(username)
        return result, 200 if ok else 400

    elif action == "change":
        if not username or not level:
            return {"error": "請提供使用者名稱與等級"}, 400
        ok, result = manager.change(username, level)
        return result, 200 if ok else 400

    elif action == "list":
        ok, result = manager.list_all_users()
        return ({"users": result}, 200) if ok else ({"error": result.get("message")}, 500)

    else:
        return {"error": "未知的操作"}, 400


#  函式：記錄訊息
def log(*args):
    now = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(now, *args)