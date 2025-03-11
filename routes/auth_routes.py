import os
import json
import base64
from flask import Blueprint, request, jsonify, session
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import parse_client_data_json
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
)
from config.config import Config

auth_bp = Blueprint("auth", __name__)
users = {}  # 模擬用戶資料庫


# 轉換 bytes 為 Base64 (避免 JSON 錯誤)
def encode_bytes_to_base64(data):
    if isinstance(data, bytes):
        return base64.b64encode(data).decode("utf-8")
    elif isinstance(data, dict):
        return {key: encode_bytes_to_base64(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [encode_bytes_to_base64(item) for item in data]
    return data


# 首頁
@auth_bp.route("/")
def home():
    # 顯示歡迎詞並且增加超連結到 /main
    return """Hello, World! <a href="/main">點擊進入 WebAuthn 環節</a>"""


# 註冊 WebAuthn 憑證
@auth_bp.route("/register", methods=["POST"])
def register():
    """產生 WebAuthn 註冊選項"""
    data = request.json
    if not data or "username" not in data:
        return jsonify({"error": "請提供 username"}), 400

    username = data["username"]
    if username in users:
        return jsonify({"error": "用戶已存在"}), 400

    user_id = os.urandom(16)  # 產生隨機用戶 ID
    users[username] = {"id": user_id}

    rp = PublicKeyCredentialRpEntity(id=Config.RP_ID, name=Config.RP_NAME)
    user = PublicKeyCredentialUserEntity(
        id=user_id, name=username, display_name=username
    )

    options = generate_registration_options(
        rp_id=rp.id,
        rp_name=rp.name,
        user_name=user.name,
        user_id=user.id,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        attestation=AttestationConveyancePreference.DIRECT,
    )

    options_json = options_to_json(options)
    users[username].update(json.loads(options_json))
    session["challenge"] = options.challenge

    return jsonify(users[username])


# 驗證 WebAuthn 憑證
@auth_bp.route("/verify-credential", methods=["POST"])
def verify_credential():
    """驗證 WebAuthn 憑證回應"""
    data = request.json
    if not data or "username" not in data or "credential" not in data:
        return jsonify({"error": "請提供 username 和 credential"}), 400

    username = data["username"]
    if username not in users:
        return jsonify({"error": "用戶不存在"}), 400

    credential_data = data["credential"]
    expected_challenge = session.get("challenge")
    if expected_challenge is None:
        return jsonify({"error": "session 的 challenge 不存在"}), 400

    try:
        response_data = credential_data["response"]
        verified_authentication = verify_authentication_response(
            credential=AuthenticationCredential(
                id=credential_data["id"],
                raw_id=base64url_to_bytes(credential_data["rawId"]),
                response=AuthenticatorAssertionResponse(
                    client_data_json=base64url_to_bytes(
                        response_data["clientDataJSON"]
                    ),
                    authenticator_data=base64url_to_bytes(
                        response_data["authenticatorData"]
                    ),
                    signature=base64url_to_bytes(response_data["signature"]),
                    user_handle=(
                        base64url_to_bytes(response_data["userHandle"])
                        if response_data["userHandle"]
                        else None
                    ),
                ),
                type=credential_data["type"],
            ),
            expected_challenge=expected_challenge,
            expected_rp_id=Config.RP_ID,
            expected_origin=Config.ORIGIN,
            credential_public_key=users[username]["credential"]["publicKey"],
            credential_current_sign_count=users[username]["credential"]["signCount"],
        )

        users[username]["credential"][
            "signCount"
        ] = verified_authentication.new_sign_count
        return jsonify({"status": "ok", "message": "成功認證"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
