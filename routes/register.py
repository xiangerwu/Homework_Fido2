"""說明
# Register 註冊路由
# 作用: 註冊 WebAuthn 憑證
# 主要有兩個功能:
# 1./register                   產生 WebAuthn 註冊選項
# 2./register/store-credential  存儲 WebAuthn 憑證
"""

""" Import Module """
# 引入 flask 模塊
from flask import Blueprint, request, jsonify, session
import os, json

# 引入 global_config 自定義模塊
from config.global_config import (
    RP_ID,
    RP_NAME,
    ORIGIN,
    base64url_to_bytes,
    encode_bytes_to_base64,
    db_users,
)

# 引入 db_manager 自定義模塊
from Database.db_manager import DatabaseManager


# 引入 fido2 模塊
from fido2.webauthn import (
    CollectedClientData,
    AttestationObject,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    PublicKeyCredentialUserEntity,
)
import app as app_server

""" Create Blueprint """
# 創建 Blueprint
register_bp = Blueprint("register", __name__)

""" Register Functions """


# 網頁路徑 /register
# 作用: 產生 WebAuthn 註冊選項
@register_bp.route("/", methods=["POST"])
def register():
    # 取得用戶提交的 JSON 數據
    data = request.json
    # 取得用戶名稱
    username = data.get("username")
    # 確認用戶是否存在
    with DatabaseManager(db_users) as db:
        chek_username = db.get_user_name(username)

    if chek_username:
        return jsonify({"error": "用戶已存在"}), 400

    # 產生隨機的用戶 ID，用於後續產生金鑰
    user_id = os.urandom(16)

    # 使用 yubiko fido2 套件開始註冊
    # 設定註冊選項
    # 這裡設定了用戶名稱、用戶 ID、用戶驗證、驗證器平台、密鑰設定
    # 這裡的設定可以根據需求進行更改
    # 這裡的 user 設定是必須的，如果不設定會報錯
    options, state = app_server.server.register_begin(
        user=PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username,
        ),
        user_verification=UserVerificationRequirement.REQUIRED,  # 驗證設定
        # authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,  # 驗證器平台
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,  # 密鑰設定
    )

    # print("options:", options)

    # 轉換 options 為 JSON 格式
    options_dict = dict(options)
    options_json = encode_bytes_to_base64(options_dict)

    # 暫存 state，其中包含 challenge 之後驗證會用到
    # session["state"] = state
    # 序列化 session["state"] 為 JSON 字串
    serialized_state = json.dumps(state)
    with DatabaseManager(db_users) as db:
        save_session = db.insert_session(username, serialized_state)
    # print("state:", state)

    # print("Add user result:", Add_User)

    # 回傳給前端 JSON 格式的 options，代表後端收到了註冊請求
    return jsonify(options_json)  # 回傳給前端


# 網頁路徑 /register/store-credential
# 作用: 存儲 WebAuthn 憑證
@register_bp.route("/store-credential", methods=["POST"])
def store_credential():
    # 取得用戶提交的 JSON
    data = request.json
    username = data.get("username")
    debug_log = []
    # 開始存儲憑證流程
    try:
        # 檢查用戶是否存在
        if not username:
            return jsonify({"error": "沒有用戶帶入用戶名稱"}), 400

        # 檢查資料是否有效，並取得憑證資料(前端)，或錯誤回傳
        clinet_credential_data = data.get("credential")
        if not clinet_credential_data:
            return jsonify({"error": "請提供有效的 JSON 數據"}), 400

        debug_log.append("1. 取得用戶提交的 JSON")
        # client_response 是前端回傳的資料
        client_response = clinet_credential_data["response"]
        # 轉換 clinet_credential_data 中相關的資料，將 base64url 字串轉為 bytes 後轉換成 fido2 的物件
        # 這裡的 CollectedClientData 是 fido2 的 CollectedClientData 物件
        Collected_ClientData = CollectedClientData(
            base64url_to_bytes(client_response["clientDataJSON"])
        )
        # 這裡的 Attestation_Object 是 fido2 的 AttestationObject 物件
        Attestation_Object = AttestationObject(
            base64url_to_bytes(client_response["attestationObject"])
        )
        debug_log.append("2. 轉換 clinet_credential_data 中相關的資料")
        # 從資料庫中取得 Session
        User_Session = None
        with DatabaseManager(db_users) as db:
            User_Session = json.loads(db.get_session(username)[0])
        if not User_Session:
            raise Exception("Session not found for the user")

        debug_log.append("2.1 取得用戶 Session")
        # 使用 yubiko fido2 套件完成註冊
        # 註冊完成後會得到 server_credential_data，這是後端需要儲存的註冊資料並且是 bytes 類型
        server_credential_data = app_server.server.register_complete(
            state=User_Session,  # 從 session 中取得 state，這是前面註冊時暫存的
            client_data=Collected_ClientData,  # 設定 client_data: 前端回傳的 clientDataJSON
            attestation_object=Attestation_Object,  # 設定 attestation_object: 前端回傳的 attestationObject
        )
        #
        debug_log.append("3. 完成註冊")
        # 將 server_credential_data 存進資料庫
        with DatabaseManager(db_users) as db:
            Add_Credential = db.insert_user(username, server_credential_data)
        debug_log.append("4. 存儲憑證")
        # 刪除 session
        with DatabaseManager(db_users) as db:
            del_session = db.delete_session(username)
        debug_log.append("5. 刪除 Session")
        # 回傳成功訊息
        return jsonify(
            {
                "status": "ok",
                "message": "憑證已存儲",
                "signCount": server_credential_data.counter,
            }
        )
    # 如果有錯誤，回傳錯誤訊息
    except Exception as e:
        return (
            jsonify({"error": str(e), "debug": debug_log}),
            400,
        )
