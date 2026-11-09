"""Phase 1 JWT + RBAC helpers for the /p1 compatibility API.

Uses stdlib HMAC-SHA256 JWTs and PBKDF2 password hashes. Users live in the
gateway SQLite database. Passwords are never logged or committed; seed only via
environment variables (see ensure_seed_users).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

ROLES = ('admin', 'operator', 'viewer')
MUTATING = {'POST', 'PUT', 'PATCH', 'DELETE'}
# Paths relative to /p1 that stay public (no JWT).
PUBLIC = {('POST', 'auth/login'), ('GET', 'status')}
# Authenticated GETs any role may call.
VIEWER_GET_PREFIXES = (
    'devices', 'device-types', 'attack-types', 'events', 'traffic', 'topology',
    'cloud', 'status', 'ws', 'network-load', 'learning-status', 'auth',
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_json(value) -> str:
    return _b64url(json.dumps(value, separators=(',', ':'), sort_keys=True).encode())


def jwt_secret(server_token: str) -> str:
    secret = os.environ.get('TRUSTEDGE_JWT_SECRET', '').strip()
    if secret:
        return secret
    # Lab/dev fallback: derive from the gateway token so one secret file can drive both.
    return 'trustedge-p1:' + server_token


def jwt_expiry_seconds() -> int:
    try:
        return max(60, int(os.environ.get('TRUSTEDGE_JWT_EXPIRY', '3600')))
    except ValueError:
        return 3600


def make_token(username: str, role: str, secret: str) -> str:
    if role not in ROLES:
        raise ValueError('invalid role')
    now = int(time.time())
    header = _b64url_json({'alg': 'HS256', 'typ': 'JWT'})
    payload = _b64url_json({'sub': username, 'role': role, 'iat': now,
                            'exp': now + jwt_expiry_seconds()})
    signing = f'{header}.{payload}'.encode()
    sig = _b64url(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return f'{header}.{payload}.{sig}'


def decode_token(token: str, secret: str) -> dict | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
        signing = f'{header_b64}.{payload_b64}'.encode()
        expected = _b64url(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig_b64):
            return None
        pad = '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        if int(payload.get('exp', 0)) < int(time.time()):
            return None
        if payload.get('role') not in ROLES or not isinstance(payload.get('sub'), str):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError('password must be at least 8 characters')
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000)
    return 'pbkdf2_sha256$260000$%s$%s' % (salt.hex(), digest.hex())


def verify_password_hash(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = encoded.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def ensure_seed_users(storage) -> list:
    """Create bootstrap users from env when the users table is empty.

    Returns usernames that were created. Requires TRUSTEDGE_ADMIN_PASSWORD.
    Optional: TRUSTEDGE_OPERATOR_PASSWORD, TRUSTEDGE_VIEWER_PASSWORD.
    """
    if storage.user_count():
        return []
    admin_pw = os.environ.get('TRUSTEDGE_ADMIN_PASSWORD', '').strip()
    if not admin_pw:
        return []
    created = []
    storage.create_user('admin', hash_password(admin_pw), 'admin')
    created.append('admin')
    operator_pw = os.environ.get('TRUSTEDGE_OPERATOR_PASSWORD', '').strip()
    if operator_pw:
        storage.create_user('operator', hash_password(operator_pw), 'operator')
        created.append('operator')
    viewer_pw = os.environ.get('TRUSTEDGE_VIEWER_PASSWORD', '').strip()
    if viewer_pw:
        storage.create_user('viewer', hash_password(viewer_pw), 'viewer')
        created.append('viewer')
    return created


def authorize(method: str, path_parts: list, bearer: str | None, secret: str):
    """Return (ok, status_code, message, principal_or_none)."""
    path_key = '/'.join(path_parts)
    if (method, path_key) in PUBLIC or (method == 'GET' and path_parts[:1] == ['status']):
        return True, 200, '', None
    if method == 'POST' and path_parts == ['auth', 'login']:
        return True, 200, '', None
    if not bearer:
        return False, 401, 'Missing Authorization: Bearer <token> header', None
    payload = decode_token(bearer, secret)
    if payload is None:
        return False, 401, 'Invalid or expired token', None
    principal = {'username': payload['sub'], 'role': payload['role']}
    # Any authenticated role may refresh its own session token.
    if method == 'POST' and path_parts == ['auth', 'refresh']:
        return True, 200, '', principal
    if method in MUTATING and principal['role'] not in ('admin', 'operator'):
        return False, 403, 'Forbidden — admin or operator role required', principal
    if path_parts[:1] == ['users'] and principal['role'] != 'admin':
        return False, 403, 'Forbidden — admin role required', principal
    if method == 'GET':
        return True, 200, '', principal
    return True, 200, '', principal
