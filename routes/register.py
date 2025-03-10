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
from global_config import (
    users,
    RP_ID,
    RP_NAME,
    ORIGIN,
    base64url_to_bytes,
    encode_bytes_to_base64,
    chek_username,
)

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
    # 檢查資料是否有效，並取得用戶名稱或回傳錯誤
    error, username = chek_username(1, data)
    if error:
        return jsonify({"error": error}), 400

    # 儲存用戶 ID
    user_id = os.urandom(16)  # 產生隨機的用戶 ID
    users[username] = {"id": user_id}  # 儲存用戶 ID
    #

    # 使用 yubiko fido2 庫設定註冊選項
    options, state = app.server.register_begin(
        PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username,
        ),
        user_verification=UserVerificationRequirement.PREFERRED,  # 驗證需求
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,  # 跨平台
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,  # 需要密鑰
    )
    # print("options:", options)

    # 轉換 options 為 JSON 格式
    options_dict = dict(options)
    options_json = encode_bytes_to_base64(options_dict)

    # 把 options_dict 儲存到 users[username] 中 (方便之後使用)
    users[username].update(options_dict)  # 合併 options_dict 到 users[username]

    # 暫存 challenge 以驗證
    session["state"] = state
    print("state:", state)
    # 回傳給前端 JSON 格式的 options，代表後端收到了註冊請求
    return jsonify(options_json)  # 回傳給前端


# 網頁路徑 /register/store-credential
# 作用: 存儲 WebAuthn 憑證
@register_bp.route("/store-credential", methods=["POST"])
def store_credential():
    # 取得用戶提交的 JSON
    data = request.json
    # 檢查資料是否有效，並取得用戶名稱與憑證資料，或回傳錯誤
    error, username, credential_data = chek_username(2, data)
    if error:
        return jsonify({"error": error}), 400

    # 開始存儲憑證
    try:

        # 轉換 credential_data 中相關的資料，將 base64url 字串轉為 bytes 後轉換成 fido2 的物件
        Collected_ClientData = CollectedClientData(
            base64url_to_bytes(credential_data["response"]["clientDataJSON"])
        )
        Attestation_Object = AttestationObject(
            base64url_to_bytes(credential_data["response"]["attestationObject"])
        )

        # 使用 yubiko fido2 庫註冊完成(要使用 yubico的轉換器)
        auth_data = app.server.register_complete(
            state=session["state"],
            client_data=Collected_ClientData,
            attestation_object=Attestation_Object,
        )

        # 存儲憑證資料
        users[username]["credential"] = auth_data

        # 回傳成功訊息
        return jsonify(
            {"status": "ok", "message": "憑證已存儲", "signCount": auth_data.counter}
        )
    # 如果有錯誤，回傳錯誤訊息
    except Exception as e:
        return jsonify({"error": str(e)}), 400
