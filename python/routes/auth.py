import os
from flask import Blueprint, request, jsonify, session
from webauthn import verify_authentication_response, base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)
from global_config import (
    users,
    RP_ID,
    RP_NAME,
    ORIGIN,
    encode_bytes_to_base64,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["POST"])
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

    # 產生新的challenge
    challenge = os.urandom(32)
    session["challenge"] = challenge

    # 更新 registration_data 中的挑戰碼
    registration_data["challenge"] = encode_bytes_to_base64(challenge)

    # 回傳給前端
    return jsonify(encode_bytes_to_base64(registration_data))


@auth_bp.route("/verify-credential", methods=["POST"])
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
        Data_response = credential_data["response"]

        verified_authentication = verify_authentication_response(
            credential=AuthenticationCredential(
                id=credential_data["id"],
                raw_id=base64url_to_bytes(credential_data["rawId"]),
                response=AuthenticatorAssertionResponse(
                    client_data_json=base64url_to_bytes(
                        Data_response["clientDataJSON"]
                    ),
                    authenticator_data=base64url_to_bytes(
                        Data_response["authenticatorData"]
                    ),
                    signature=base64url_to_bytes(Data_response["signature"]),
                    user_handle=(
                        base64url_to_bytes(Data_response["userHandle"])
                        if Data_response["userHandle"]
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
