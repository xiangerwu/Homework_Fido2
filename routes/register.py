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
from config.db_manager import db_operation, chek_username

# 引入 app
import app

# 引入 fido2 模塊
from fido2.webauthn import (
    CollectedClientData,
    AttestationObject,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    PublicKeyCredentialUserEntity,
)
from fido2.server import Fido2Server

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
    # 檢查資料是否有效，並取得用戶名稱或錯誤回傳
    error, username = chek_username(1, data)
    if error:
        return jsonify({"error": error}), 400

    # 產生隨機的用戶 ID，用於後續產生金鑰
    user_id = os.urandom(16)

    # 使用 yubiko fido2 套件開始註冊
    # 設定註冊選項
    # 這裡設定了用戶名稱、用戶 ID、用戶驗證、驗證器平台、密鑰設定
    # 這裡的設定可以根據需求進行更改
    # 這裡的 user 設定是必須的，如果不設定會報錯
    options, state = app.server.register_begin(
        user=PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username,
        ),
        user_verification=UserVerificationRequirement.REQUIRED,  # 驗證設定
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,  # 驗證器平台
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,  # 密鑰設定
    )

    # print("options:", options)

    # 轉換 options 為 JSON 格式
    options_dict = dict(options)
    options_json = encode_bytes_to_base64(options_dict)

    # 暫存 state，其中包含 challenge 之後驗證會用到
    session["state"] = state
    # print("state:", state)

    # 將用戶名稱與用戶 ID 寫入資料庫
    Add_User = db_operation(
        db_users,
        "insert",
        "INSERT INTO Users (User_name, User_id) VALUES (?, ?)",
        (username, user_id),
    )

    # print("Add user result:", Add_User)

    # 回傳給前端 JSON 格式的 options，代表後端收到了註冊請求
    return jsonify(options_json)  # 回傳給前端


# 網頁路徑 /register/store-credential
# 作用: 存儲 WebAuthn 憑證
@register_bp.route("/store-credential", methods=["POST"])
def store_credential():

    # 取得用戶提交的 JSON
    data = request.json
    # 檢查資料是否有效，並取得用戶名稱與憑證資料(前端)，或錯誤回傳
    error, username, clinet_credential_data = chek_username(2, data)
    if error:
        return jsonify({"error": error}), 400

    # 開始存儲憑證
    try:
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

        # 使用 yubiko fido2 套件完成註冊
        # 註冊完成後會得到 server_credential_data，這是後端需要儲存的註冊資料並且是 bytes 類型
        server_credential_data = app.server.register_complete(
            state=session["state"],  # 從 session 中取得 state，這是前面註冊時暫存的
            client_data=Collected_ClientData,  # 設定 client_data: 前端回傳的 clientDataJSON
            attestation_object=Attestation_Object,  # 設定 attestation_object: 前端回傳的 attestationObject
        )
        #
        # 將 server_credential_data 存進資料庫
        Add_Credential = db_operation(
            db_users,
            "insert",
            "INSERT INTO Credential (User_name, Credential) VALUES (?, ?)",
            (username, server_credential_data),
        )
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
        return jsonify({"error": str(e)}), 400
