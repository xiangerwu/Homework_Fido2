"""說明
# auth 路由
# 這個路由用於驗證 WebAuthn 憑證
# 主要有兩個路由
# 1. /verify-register   驗證 WebAuthn 註冊資料
# 2. /verify-credential 驗證 WebAuthn 憑證資料
"""

""" Import Module """
# 引入 os 模塊
import os

# 引入 flask 模塊
from flask import Blueprint, request, jsonify, session

# 引入 global_config 自定義模塊
from global_config import (
    users,
    RP_ID,
    RP_NAME,
    ORIGIN,
    encode_bytes_to_base64,
    base64url_to_bytes,
    chek_username,
)

# 引入 app
import app

# 引入 fido2 模塊
from fido2.webauthn import (
    AttestedCredentialData,
    CollectedClientData,
    UserVerificationRequirement,
    AuthenticatorData,
    AuthenticationResponse,
    webauthn_json_mapping,
)
from fido2.server import Fido2Server

# 啟用 WebAuthn JSON 映射
webauthn_json_mapping.enabled = True
""" Create Blueprint """
# 創建 Blueprint
auth_bp = Blueprint("auth", __name__)

""" Auth Functions """


# 網頁路徑 /verify-register
# 作用: 驗證 WebAuthn 註冊資料
@auth_bp.route("/", methods=["POST"])
def verify_register():
    # 取得用戶提交的 JSON 數據
    data = request.json
    # 檢查資料是否有效，並取得使用者註冊資料或回傳錯誤
    error, registration_data = chek_username(3, data)
    if error:
        return jsonify({"error": error}), 400
    # 產生新的challenge
    challenge = os.urandom(32)
    # 儲存 challenge 到 session
    session["state"] = {"challenge": challenge}

    # 將資料打包為 AttestedCredentialData 格式
    registration_credential_data = AttestedCredentialData.create(
        aaguid=bytes(registration_data.credential_data.aaguid),
        credential_id=registration_data.credential_data.credential_id,
        public_key=registration_data.credential_data.public_key,
    )
    # 開始註冊
    options, state = app.server.authenticate_begin(
        credentials=[registration_credential_data],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    # 更新 session 中的 state
    session["state"] = state
    # 顯示 Auth state
    print("Auth state:", state)
    # 轉換 options 為 JSON 格式
    options_dict = dict(options)
    options_json = encode_bytes_to_base64(options_dict)
    return jsonify(options_json)


# 網頁路徑 /verify-credential
# 作用: 驗證 WebAuthn 憑證回應
@auth_bp.route("/verify-credential", methods=["POST"])
def verify_credential():

    # 取得用戶提交的 JSON 數據
    data = request.json
    # 檢查資料是否有效，並取得前端註冊資料或回傳錯誤
    error, username, credential_data = chek_username(4, data)
    if error:
        return jsonify({"error": error}), 400

    # expected_challenge 用來驗證 session 中的 challenge
    expected_challenge = session.get("state", {}).get("challenge", None)
    if expected_challenge is None:
        return jsonify({"error": "session 的 challenge 不存在"}), 400

    # 驗證憑證流程
    try:

        # 從[用戶註冊的憑證資料]取得 attested_data (這裡的 credential_data 不是前端回傳的 )
        # 用來塞進 Credentials
        attested_data = users[username]["credential"].credential_data

        # 使用 cred_response 縮短後續程式碼(前端回傳的資料)
        cred_response = credential_data["response"]

        """""" """""" """ 將後面 authenticate_complete 要用的變數先拉出來整理 """ """""" """"""

        """ credentials """
        # 將 attested_data 轉換為 AttestedCredentialData 格式
        # 是後端儲存的註冊資料
        Credentials = [
            AttestedCredentialData.create(
                aaguid=bytes(attested_data.aaguid),
                credential_id=attested_data.credential_id,
                public_key=attested_data.public_key,
            )
        ]

        """ auth_data (沒用到但計數器目前需要) """
        ## 解析 authenticatorData
        ## 取得驗證資訊(前端回傳的資料)
        parsed_auth_data = AuthenticatorData(
            base64url_to_bytes(cred_response["authenticatorData"])
        )

        """ response """
        # 將 cred_response 轉換為 AuthenticationResponse 格式(前端回傳的資料)
        Response = AuthenticationResponse(
            id=base64url_to_bytes(credential_data["id"]),
            response={
                "clientDataJSON": base64url_to_bytes(cred_response["clientDataJSON"]),
                "authenticatorData": base64url_to_bytes(
                    cred_response["authenticatorData"]
                ),
                "signature": base64url_to_bytes(cred_response["signature"]),
            },
        )

        """""" """""" """ 區塊結束 """ """""" """"""

        # 使用 authenticate_complete 進行完整驗證
        auth_result = app.server.authenticate_complete(
            state=session["state"], credentials=Credentials, response=Response
        )

        # 更新 users[username]["credential"]
        users[username]["credential"] = AuthenticatorData.create(
            rp_id_hash=users[username]["credential"].rp_id_hash,
            flags=users[username]["credential"].flags,
            counter=parsed_auth_data.counter,  # ✅ 更新計數器
            credential_data=users[username]["credential"].credential_data,
            extensions=users[username]["credential"].extensions,
        )

        # 回傳成功訊息
        return jsonify(
            {
                "status": "ok",
                "message": "成功認證",
                "signCount": parsed_auth_data.counter,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400
