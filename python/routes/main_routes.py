import os
import json
import base64
from flask import Flask, render_template, request, jsonify, session, Blueprint
from flask_cors import CORS
from flask_sslify import SSLify
from flask_sqlalchemy import SQLAlchemy

# 引入自用 SQL config
from python.config.SQLite_config import SQLite_config

# 引入自用 models/ user.py
from models.user import SQL_db, User

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)

from webauthn.helpers import parse_client_data_json, byteslike_to_bytes


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
    AuthenticatorAttachment,
)

main_bp = Blueprint("main", __name__)
