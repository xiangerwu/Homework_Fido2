import os
import json
import base64
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_sslify import SSLify

from webauthn.helpers.options_to_json import options_to_json
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)

from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    AuthenticatorAssertionResponse,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    ResidentKeyRequirement,
)


app = Flask(__name__)
CORS(app, supports_credentials=True)
sslify = SSLify(app)
app.secret_key = os.urandom(24)  # 設定 Session 金鑰

# RP (Relying Party) 服務端資訊
RP_ID = "localhost"  # 你的網域
RP_NAME = "My WebAuthn App"
ORIGIN = "https://localhost:5000"

# 模擬用戶資料庫
users = {}


# 首頁
@app.route("/")
def home():
    # 顯示歡迎詞並且增加超連結到 /main
    return """Hello, World! <a href="/main">點擊進入 WebAuthn 環節</a>"""


# 主要瀏覽 index.html
@app.route("/main")
def main():
    return render_template("index.html")


# 註冊頁面 /register
@app.route("/register", methods=["POST"])
def register():
    """產生 WebAuthn 註冊選項"""
    # 取得用戶提交的 JSON 數據
    data = request.json
    # 如果沒有數據，回傳錯誤
    if data is None:
        return jsonify({"error": "請提供有效的 JSON 數據"}), 400
    username = data.get("username")
    # 如果沒有用戶名，回傳錯誤
    if not username:
        return jsonify({"error": "請提供 username"}), 400
    # 如果用戶已存在，回傳錯誤
    if username in users:
        return jsonify({"error": "用戶已存在"}), 400

    # 產生並儲存 用戶 ID
    user_id = os.urandom(16)  # 產生隨機的用戶 ID
    users[username] = {"id": user_id}  # 儲存用戶 ID

    # 後端產生 RP (Relying Party) 與用戶資訊
    rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
    user = PublicKeyCredentialUserEntity(
        id=user_id, name=username, display_name=username
    )
    # 後端將註冊資料 包裝成 options
    options = generate_registration_options(
        rp_id=rp.id,  # RP ID
        rp_name=rp.name,  # RP 名稱
        user_name=user.name,  # 用戶名稱
        user_id=user.id,  # 用戶 ID
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        attestation=AttestationConveyancePreference.DIRECT,
    )

    # 使用 options_to_json 函式將 options 轉換為 JSON 類型
    options_json = options_to_json(options)

    # 把 options_json 儲存到 users[username] 中 (方便之後回傳)
    options_dict = json.loads(options_json)  # 將 JSON 解析回 Python 字典
    users[username].update(options_dict)  # 合併 options_dict 到 users[username]

    # 暫存 challenge 以驗證
    session["challenge"] = options.challenge
    # 回傳給前端 JSON 格式的 options，代表後端收到了註冊請求並記錄了 challenge
    return jsonify(json.loads(options_json))  # 回傳給前端


# 驗證註冊回應 /verify-register
@app.route("/verify-register", methods=["POST"])
def verify_register():
    """驗證 WebAuthn 註冊回應"""
    data = request.json
    if data is None:
        return jsonify({"error": "請提供有效的 JSON 數據"}), 400

    # 取得用戶名稱
    username = data.get("username")
    # 如果用戶不存在，回傳錯誤
    if username not in users:
        return jsonify({"error": "用戶不存在"}), 400

    # 查詢 users[username] 中的註冊資料
    registration_data = users[username]
    # 如果註冊資料不存在，回傳錯誤
    if registration_data is None:
        return jsonify({"error": "註冊資料不存在"}), 400

    # 將 bytes 類型數據轉換為 Base64 編碼
    # 先判斷 registration_data 中id 是否為 bytes 類型，如果是，則轉換為 Base64 編碼
    if isinstance(registration_data["id"], bytes):
        registration_data["id"] = base64.b64encode(registration_data["id"]).decode(
            "utf-8"
        )

    if "challenge" in registration_data and isinstance(
        registration_data["challenge"], bytes
    ):
        registration_data["challenge"] = base64.b64encode(
            registration_data["challenge"]
        ).decode("utf-8")

    # 存在的話，取得註冊資料後打包成前端可以接收的格式
    registration_data = json.dumps(registration_data)
    # 回傳給前端
    return jsonify(json.loads(registration_data))


# 存儲憑證 /store-credential
@app.route("/store-credential", methods=["POST"])
def store_credential():
    """存儲 WebAuthn 憑證"""
    data = request.json
    if data is None:
        return jsonify({"error": "請提供有效的 JSON 數據"}), 400

    username = data.get("username")
    if username not in users:
        return jsonify({"error": "用戶不存在"}), 400

    credential_data = data.get("credential")
    if credential_data is None:
        return jsonify({"error": "請提供 credential"}), 400

    try:
        # 驗證註冊回應
        verified_registration = verify_registration_response(
            credential=RegistrationCredential(
                id=credential_data["id"],
                raw_id=base64url_to_bytes(credential_data["rawId"]),
                response=AuthenticatorAttestationResponse(
                    attestation_object=base64url_to_bytes(
                        credential_data["response"]["attestationObject"]
                    ),
                    client_data_json=base64url_to_bytes(
                        credential_data["response"]["clientDataJSON"]
                    ),
                ),
                type=credential_data["type"],
            ),
            expected_challenge=base64url_to_bytes(session["challenge"]),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )

        # 存儲憑證資料
        users[username]["credential"] = {
            "id": verified_registration.credential_id,
            "publicKey": verified_registration.credential_public_key,
            "signCount": verified_registration.sign_count,
        }

        return jsonify({"status": "ok", "message": "憑證已存儲"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# 驗證憑證回應 /verify-credential
@app.route("/verify-credential", methods=["POST"])
def verify_credential():
    """驗證 WebAuthn 憑證回應"""
    data = request.json
    if data is None:
        return jsonify({"error": "請提供有效的 JSON 數據"}), 400

    username = data.get("username")
    if username not in users:
        return jsonify({"error": "用戶不存在"}), 400

    credential_data = data.get("credential")
    if credential_data is None:
        return jsonify({"error": "請提供 credential"}), 400

    expected_challenge = session.get("challenge", None)
    if expected_challenge is None:
        return jsonify({"error": "session 的 challenge 不存在"}), 400

    try:
        verified_authentication = verify_authentication_response(
            credential=AuthenticationCredential(
                id=credential_data["id"],
                raw_id=base64url_to_bytes(credential_data["rawId"]),
                response=AuthenticatorAssertionResponse(
                    client_data_json=base64url_to_bytes(
                        credential_data["response"]["clientDataJSON"]
                    ),
                    authenticator_data=base64url_to_bytes(
                        credential_data["response"]["authenticatorData"]
                    ),
                    signature=base64url_to_bytes(
                        credential_data["response"]["signature"]
                    ),
                    user_handle=(
                        base64url_to_bytes(credential_data["response"]["userHandle"])
                        if credential_data["response"]["userHandle"]
                        else None
                    ),
                ),
                type=credential_data["type"],
            ),
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=users[username]["credential"]["publicKey"],
            credential_current_sign_count=users[username]["credential"]["signCount"],
        )

        users[username]["credential"][
            "signCount"
        ] = verified_authentication.new_sign_count

        return jsonify({"status": "ok", "message": "成功認證"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# 清除用戶資料 /clear
@app.route("/clear", methods=["POST"])
def clear():
    """清除全部用戶資料"""
    # data = request.json
    # if data is None:
    #     return jsonify({"error": "請提供有效的 JSON 數據"}), 400
    # username = data.get("username")
    users.clear()
    return jsonify({"status": "ok", "message": "用戶資料已清除"})


# 啟動伺服器
if __name__ == "__main__":
    context = ("localhost.pem", "localhost-key.pem")  # SSL 憑證
    app.run(debug=True, ssl_context=context)  # 啟動伺服器

# TODO: 1. 還缺少 auth 機制 呼叫瀏覽器的 WebAuthn API 確認金鑰是否存在
