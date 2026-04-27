from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass

_ITERATIONS = 240_000


def hash_password(password: str, salt: str | None = None) -> str:
    salt_bytes = base64.b64decode(salt) if salt else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${base64.b64encode(salt_bytes).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, iterations, salt, digest = encoded.split("$", 3)
    except ValueError:
        return False
    if method != "pbkdf2_sha256":
        return False
    test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt), int(iterations))
    return hmac.compare_digest(base64.b64encode(test).decode(), digest)


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp(secret: str, interval: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded.upper())
    msg = struct.pack(">Q", interval)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_totp(secret: str, code: str, now: int | None = None, window: int = 1) -> bool:
    if not code or not code.isdigit():
        return False
    current = int((now or time.time()) // 30)
    return any(hmac.compare_digest(_totp(secret, current + offset), code) for offset in range(-window, window + 1))


def otpauth_uri(email: str, secret: str, issuer: str = "Gcmgamesync") -> str:
    return f"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


@dataclass(frozen=True)
class Session:
    token: str
    email: str
    is_admin: bool


def new_token() -> str:
    return secrets.token_urlsafe(32)
