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
from config.global_config import (
    RP_ID,
    RP_NAME,
    ORIGIN,
    encode_bytes_to_base64,
    base64url_to_bytes,
    db_users,
)

# 引入 db_manager 自定義模塊
from config.db_manager import DatabaseManager

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

from user_agents import parse

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
    username = data.get("username")
    if not username:
        return jsonify({"error": "請提供使用者名稱"}), 400
    try:
        # 檢查資料是否有效，並取得使用者註冊資料(後端)或錯誤回傳
        with DatabaseManager(db_users) as db:
            server_credential_data = db.get_credential(data.get("username"))[0]
        if not server_credential_data:
            return jsonify({"error": "用戶註冊憑證不存在"}), 400

        # 這時 server_credential_data 是後端儲存的註冊資料並且是 bytes 類型
        # 這裡將料轉換為 fido2 的 Authenticator 物件
        restored_server_credential_data = AuthenticatorData(server_credential_data)
        # 提取 restored_server_credential_data 中的 credential_data
        Credential_data = restored_server_credential_data.credential_data
        # 將資料打包為 fido2 的 AttestedCredentialData 格式
        AttestedCredential = AttestedCredentialData.create(
            aaguid=bytes(Credential_data.aaguid),  # 設定 aagui: 驗證設備是否支援
            credential_id=Credential_data.credential_id,  # 設定 credential_id: 憑證 ID
            public_key=Credential_data.public_key,  # 設定 public_key: 公鑰
        )

        # 使用 yubiko fido2 套件開始驗證
        # 這裡設定了驗證選項，並且設定了驗證設備的要求
        options, state = app.server.authenticate_begin(
            credentials=[AttestedCredential],  # 設定 credentials: 後端儲存的註冊資料
            user_verification=UserVerificationRequirement.REQUIRED,  # 驗證設定
            
        )

        # 更新 session 中的 state
        session["state"] = state
        # 顯示 state
        # print("Auth state:", state)
        # 轉換 options 為 JSON 格式
        options_dict = dict(options)
        options_json = encode_bytes_to_base64(options_dict)
        # 回傳 options
        return jsonify(options_json)

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# 網頁路徑 /verify-credential
# 作用: 驗證 WebAuthn 憑證回應
@auth_bp.route("/verify-credential", methods=["POST"])
def verify_credential():

    # 取得用戶提交的 JSON 數據
    data = request.json
    username = data.get("username")
    if not username:
        return jsonify({"error": "請提供使用者名稱"}), 400
    # 驗證憑證流程
    try:
        # 檢查資料是否有效，並取得註冊資料(前端)或錯誤回傳
        client_credential_data = data.get("credential")
        if not client_credential_data:
            return jsonify({"error": "錯誤的 credential"}), 400

        # expected_challenge 用來驗證 session 中的 challenge
        # 這是前面步驟的 challenge
        expected_challenge = session.get("state", {}).get("challenge", None)
        if expected_challenge is None:
            return jsonify({"error": "session 的 challenge 不存在"}), 400

        # 從後端資料庫中取得 Credential 資料
        # 這裡的 server_credential_data 是後端儲存的註冊資料，並且是 bytes
        with DatabaseManager(db_users) as db:
            server_credential_data = db.get_credential(username)[0]
        if not server_credential_data:
            return jsonify({"error": "資料庫中的用戶憑證不存在"}), 400

        # 這裡將 bytes 資料轉換為 Authenticator
        restored_server_credential_data = AuthenticatorData(server_credential_data)
        # 提取 restored_server_credential_data 中的 credential_data
        attested_data = restored_server_credential_data.credential_data
        #
        # 使用 client_response 縮短後續程式碼
        client_response = client_credential_data["response"]
        # 紀錄驗證器資訊
        authenticator_type = client_credential_data["type"]
        """!!! 將後面 authenticate_complete 要用的變數先拉出來整理 !!!"""

        """ credentials """
        # 是後端儲存的註冊資料
        # 將 attested_data 轉換為 AttestedCredentialData 格式
        Server_Credentials = [
            AttestedCredentialData.create(
                aaguid=bytes(attested_data.aaguid),
                credential_id=attested_data.credential_id,
                public_key=attested_data.public_key,
            )
        ]

        """<<沒用到>> auth_data (計數器需要) """
        ## 解析 authenticatorData
        ## 取得驗證資訊(前端回傳的資料)
        parsed_auth_data = AuthenticatorData(
            base64url_to_bytes(client_response["authenticatorData"])
        )

        """ response """
        # 將前端回傳的 client_response 轉換為 AuthenticationResponse 格式
        Client_Response = AuthenticationResponse(
            id=base64url_to_bytes(client_credential_data["id"]),
            response={
                "clientDataJSON": base64url_to_bytes(client_response["clientDataJSON"]),
                "authenticatorData": base64url_to_bytes(
                    client_response["authenticatorData"]
                ),
                "signature": base64url_to_bytes(client_response["signature"]),
            },
        )

        """""" """""" """ 區塊結束 """ """""" """"""

        # 使用 yubiko fido2 套件完成驗證
        # 這裡的 auth_result 是後端驗證後的結果
        auth_result = app.server.authenticate_complete(
            state=session["state"],  # 從 session 中取得 state
            credentials=Server_Credentials,  # 後端儲存的註冊資料
            response=Client_Response,  # 前端回傳的 client_response
        )

        # 成功驗證後，記錄登入資訊到 Users_Log
        # 分析 request 中的資料
        User_Log = Login_Log(username,request,authenticator_type)

        # 回傳成功訊息
        return jsonify(
            {
                "status": "ok",
                "message": "成功認證",
                "signCount": parsed_auth_data.counter,
            }
        )
    except Exception as e:
        print("error:", e)  # 顯示錯誤訊息
        return jsonify({"error": str(e)}), 400



def Login_Log(username,request,authenticator_type):
    try:
        user_agent= parse(request.headers.get("User-Agent"))
        user_ip = request.remote_addr
        user_device = user_agent.device.family
        # 判斷是不是手機
        device_types = {
            "PC": user_agent.is_pc,
            "Mobile": user_agent.is_mobile,
            "Tablet": user_agent.is_tablet
        }
        for key, value in device_types.items():
            if value:
                user_device = key
        
        user_os = user_agent.os.family
        user_browser = user_agent.browser.family
        with DatabaseManager(db_users) as db:
            db.log_user_login(username, authenticator_type, user_ip, user_os, user_device, user_browser)
        # 這裡應該要寫入資料庫
        return None
    except Exception as e:
        raise Exception("Log Error")