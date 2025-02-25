from flask import Blueprint, request, jsonify, session
import os, json
from global_config import users, RP_ID, RP_NAME, ORIGIN


from webauthn import (
    generate_registration_options,
    options_to_json,
    base64url_to_bytes,
    verify_registration_response,
)
from webauthn.helpers import parse_client_data_json, byteslike_to_bytes
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorAttestationResponse,
    RegistrationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
)

register_bp = Blueprint("register", __name__)


@register_bp.route("/", methods=["POST"])
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
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
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
    return jsonify(options_dict)  # 回傳給前端


@register_bp.route("/store-credential", methods=["POST"])
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

        response_data = credential_data["response"]
        client_data_bytes = base64url_to_bytes(response_data["clientDataJSON"])
        client_data = parse_client_data_json(client_data_bytes)

        # 驗證註冊回應
        verified_registration = verify_registration_response(
            credential=RegistrationCredential(
                id=credential_data["id"],
                raw_id=base64url_to_bytes(credential_data["rawId"]),
                response=AuthenticatorAttestationResponse(
                    attestation_object=base64url_to_bytes(
                        credential_data["response"]["attestationObject"]
                    ),
                    client_data_json=client_data_bytes,
                ),
                type=credential_data["type"],
            ),
            expected_challenge=client_data.challenge,
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
