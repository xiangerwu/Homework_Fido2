"""說明
# authentication 路由
# 這個路由用於驗證 WebAuthn 憑證
# 主要有兩個路由
# 1. /verify-register   驗證 WebAuthn 註冊資料
# 2. /verify-credential 驗證 WebAuthn 憑證資料
"""

""" Import Module """
# 引入 模塊
import  json
import re
# 引入 flask 模塊
from flask import (
    Blueprint, 
    request, 
    jsonify, 
    session, 
    make_response , 
    Response
)


# 引入 global_config 自定義模塊
from config.global_config import (
    RP_ID,
    RP_NAME,
    ORIGIN,
    encode_bytes_to_base64,
    base64url_to_bytes,
    db_users,
    sanitize_username,
    unsanitize_username,
    generate_jwt,
)

# 引入 db_manager 自定義模塊
from Database.db_manager import DatabaseManager

# 引入 fido2 模塊
from fido2.webauthn import (
    AttestedCredentialData,
    UserVerificationRequirement,
    AuthenticatorData,
    AuthenticationResponse,
    webauthn_json_mapping,
)

from app import server as app_server
from user_agents import parse

# 啟用 WebAuthn JSON 映射
webauthn_json_mapping.enabled = True
""" Create Blueprint """
# 創建 Blueprint
auth_bp = Blueprint("auth", __name__)

""" Auth Functions """

# 網頁路徑 /verify-username
# 作用: 驗證 WebAuthn 註冊資料
@auth_bp.route("/verify-username", methods=["POST"], strict_slashes=False)
def verify_register():
    # 取得用戶提交的 JSON 數據，並檢查用戶名稱
    print("authentication - verify_register")
    data = request.json
    username = sanitize_username(data.get("username"))
    if not username:
        return jsonify({"error": "請提供使用者名稱"}), 400
    try:
        print("authentication - 取得使用者註冊資料,username=", username)
        # 檢查資料是否有效，並取得使用者註冊資料(後端)或錯誤回傳
        with DatabaseManager(db_users) as db:
            print("authentication - 檢查資料庫是否有效")
            db_credential_data = db.get_credential(username)
        if not db_credential_data:
            print("authentication - 用戶不存在")
            return jsonify({"error": "用戶不存在"}), 400
        server_credential_data = db_credential_data[0]
        print("authentication - 轉換 fido2 的 Authenticator 物件")
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

        print("authentication - 使用 yubiko fido2 套件開始驗證")
        # 使用 yubiko fido2 套件開始驗證
        # 這裡設定了驗證選項，並且設定了驗證設備的要求
        options, state = app_server.authenticate_begin(
            credentials=[AttestedCredential],  # 設定 credentials: 後端儲存的註冊資料
            user_verification=UserVerificationRequirement.REQUIRED,  # 驗證設定
        )

        print("authentication - 更新 session")
        # 更新 session 中的 state
        # 將 state 序列化為 JSON 格式
        serialized_state = json.dumps(state)
        # 將 state 儲存到資料庫
        with DatabaseManager(db_users) as db:
            # 檢查 Session 是否存在，如果存在則刪除
            check_session = db.get_session(username)
            if check_session:
                del_session = db.delete_session(username)
            # 儲存 Session
            save_session = db.insert_session(username, serialized_state)
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
@auth_bp.route("verify-credential", methods=["POST"], strict_slashes=False)
def verify_credential():
    debug_log = []
    # 取得用戶提交的 JSON 數據
    data = request.json
    username = sanitize_username(data.get("username"))
     # 安全取得 source 與 dist（可選）
    extra_source = data.get("source", None)
    extra_dist = data.get("dist", None)
    # 可加 debug 確認是否有帶入
    debug_log.append(f"來源: {extra_source}, 目的地: {extra_dist}")
    # 
    if not username:
        return jsonify({"error": "請提供使用者名稱"}), 400
    # 驗證憑證流程
    debug_log.append("驗證憑證流程")
    try:
        # 檢查資料是否有效，並取得註冊資料(前端)或錯誤回傳
        client_credential_data = data.get("credential")
        if not client_credential_data:
            return jsonify({"error": "錯誤的 credential"}), 400

        # 從後端資料庫中取得 Credential 資料
        # 這裡的 server_credential_data 是後端儲存的註冊資料，並且是 bytes
        with DatabaseManager(db_users) as db:
            server_credential_data = db.get_credential(username)[0]
        if not server_credential_data:
            return jsonify({"error": "資料庫中的用戶憑證不存在"}), 400

        debug_log.append("取得後端資料庫中的 Credential 資料")

        # 這裡將 bytes 資料轉換為 Authenticator
        restored_server_credential_data = AuthenticatorData(server_credential_data)
        debug_log.append("轉換後端資料庫中的 Credential 資料為 AuthenticatorData")
        # 提取 restored_server_credential_data 中的 credential_data
        attested_data = restored_server_credential_data.credential_data
        debug_log.append("提取 restored_server_credential_data 中的 credential_data")
        #
        # 使用 client_response 縮短後續程式碼
        client_response = client_credential_data["response"]
        debug_log.append("使用 client_response 縮短後續程式碼")
        # 紀錄驗證器資訊
        authenticator_type = client_credential_data["type"]
        debug_log.append("紀錄驗證器資訊")
        #
        """ 區塊開始 """
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
        debug_log.append("整理 Server_Credentials")
        """<<沒用到>> auth_data (計數器需要) """
        ## 解析 authenticatorData
        ## 取得驗證資訊(前端回傳的資料)
        parsed_auth_data = AuthenticatorData(
            base64url_to_bytes(client_response["authenticatorData"])
        )
        debug_log.append("解析 authenticatorData")

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
        debug_log.append("轉換 client_response 為 AuthenticationResponse 格式")
        #
        # 這裡的 User_Session 是後端儲存的 session 資料
        User_Session = None
        with DatabaseManager(db_users) as db:
            User_Session = json.loads(db.get_session(username)[0])
        if not User_Session:
            raise Exception("Session not found for the user")
        #
        debug_log.append("取得用戶 Session")

        """ 區塊結束 """
        #
        # 使用 yubiko fido2 套件完成驗證
        # 這裡的 auth_result 是後端驗證後的結果
        auth_result = app_server.authenticate_complete(
            state=User_Session,  # 從 session 中取得 state
            credentials=Server_Credentials,  # 後端儲存的註冊資料
            response=Client_Response,  # 前端回傳的 client_response
        )
        debug_log.append("完成驗證")
        # 成功驗證後，記錄登入資訊到 Users_Log
        User_Log = Login_Log(username, request, authenticator_type, 1)

        # 產生 JWT Token
        JWT_Token = None
        if auth_result:
            # 從網址中解析是否來自其他網站
            from_oauth = "from_oauth" in request.args
            debug_log.append("generate_fido2_jwt")
            #             
            resolved_source = extra_source  or ORIGIN # or 會自動選擇第一個非空值    
            resolved_dist   = extra_dist    or RP_ID
            # 產生 未加密的 JWT 用於確認驗證成功
            JWT_Token = generate_fido2_jwt_response(
                username=username,
                aaguid=attested_data.aaguid.hex(),
                sign_count=parsed_auth_data.counter,
                source=resolved_source,
                destination=resolved_dist
            )
            # 建立回傳格式（含 token）
            response = jsonify({
                "status": "ok",
                "message": "成功認證",
                "token": JWT_Token 
            })
            # 回傳
            return response
        else:
            return jsonify({"error": "登入驗證失敗"}), 400
    # 如果有錯誤，回傳錯誤訊息
    except Exception as e:
        print("error:", e)  # 顯示錯誤訊息
        User_Log = Login_Log(username, request, authenticator_type, 0)
        return jsonify({"error": str(e), "debug": debug_log}), 400

    # 最後清除 Session
    finally:
        # 清除 Session
        with DatabaseManager(db_users) as db:
            db.delete_session(username)


# 記錄用戶登入紀錄
def Login_Log(username, request, authenticator_type, status):
    try:
        user_agent = parse(request.headers.get("User-Agent"))
        user_ip = request.headers.get("CF-Connecting-IP") or request.remote_addr
        user_device = user_agent.device.family
        # 判斷是不是手機
        device_types = {
            "PC": user_agent.is_pc,
            "Mobile": user_agent.is_mobile,
            "Tablet": user_agent.is_tablet,
        }
        for key, value in device_types.items():
            if value:
                user_device = key

        user_os = user_agent.os.family
        user_browser = user_agent.browser.family
        with DatabaseManager(db_users) as db:
            db.log_user_login(
                username,
                authenticator_type,
                user_ip,
                user_os,
                user_device,
                user_browser,
                user_status=status,
            )

        return None
    except Exception as e:
        raise Exception("Log Error")


# 獲取用戶登入紀錄
@auth_bp.route("user-log", methods=["POST"])
def get_user_login_log():
    username = sanitize_username(request.json.get("username"))
    user_record = []
    try:
        with DatabaseManager(db_users) as db:
            user_log = db.get_user_log(username)
            for record in user_log:
                user_record.append(
                    {
                        "username": unsanitize_username(record[1]),
                        "authenticator": record[2],
                        "ip": record[3],
                        "os": record[4],
                        "device": record[5],
                        "browser": record[6],
                        "loginTime": record[7],
                        "loginStatus": record[8],
                    }
                )

        return user_record
    except Exception as e:
        raise Exception("Get User Log Error")


def generate_jwt_response(
    username: str,
    aaguid: str,
    sign_count: int,
    source: str,
    destination: str,
    from_oauth: bool,
):
    """
    根據使用者資訊產生 JWT，並建立含 JWT 的 HTTP 回應與 Cookie。
    
    參數:
        username (str): 使用者帳號
        aaguid (str): 裝置 AAGUID
        sign_count (int): 簽章次數
        source (str): JWT 來源站
        destination (str): JWT 目的站
        from_oauth (bool): 是否來自 OAuth 流程

    回傳:
        Flask Response：內含 JWT 與登入訊息
    """

    # 設定有效時間
    if not from_oauth:
        jwt_exp_min = 60           # JWT 有效分鐘
        cookie_exp_sec = 3600      # Cookie 有效秒數
    else:
        jwt_exp_min = 0.3
        cookie_exp_sec = 25

    # 產生 JWT
    jwt_token = generate_jwt(
        username=username,
        aaguid=aaguid,
        sign_count=sign_count,
        source=source,
        destination=destination,
        role="user"
    )
    # if from_oauth:
        # tokenName =  re.sub(r'\W+', '_', source) + "_token"
    # else:
    tokenName = "fido2_token"
    # ⬇⬇⬇ 回傳 JSON 給前端用於 postMessage 傳回 B（跨站 OAuth 流程用）
    # 這份 JWT 是給前端 JavaScript 用來傳回給 opener（B 網站），不是靠 Cookie 帶出
    response = make_response(jsonify({
        "status": "ok",
        "message": "成功認證",
        "signCount": sign_count,
    }))

    # ⬇⬇⬇ 同時寫入 JWT 到 Cookie，給本網站（A）後續請求驗證使用
    # 這份 JWT 是 A 自己用的，用來支援非 OAuth 的情境（例如直接登入 A 網站）
    response.set_cookie(
        key=tokenName,
        value=jwt_token,
        secure=True,
        samesite="None",
        max_age=cookie_exp_sec,
        path="/"
    )

    return response


def generate_fido2_jwt_response(
    username: str,
    aaguid: str,
    sign_count: int,
    source: str,
    destination: str,
):
    """
    建立純 JSON JWT 回應，給非 OAuth 流程的 FIDO2 驗證使用。

    回傳:
        Flask Response: JSON 格式回傳 JWT
    """

    # 產生 JWT（照原本的 generate_jwt 函式）
    jwt_token = generate_jwt(
        username=username,
        aaguid=aaguid,
        sign_count=sign_count,
        source=source,
        destination=destination,
        role="user"
    )
    return jwt_token
