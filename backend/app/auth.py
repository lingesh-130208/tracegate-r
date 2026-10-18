"""Password and opaque-token primitives for TraceGate-R authentication.

The API stores only scrypt password hashes and hashes of session/CSRF tokens.
User, session, tenancy, and authorization policy live in ``main.py`` beside
the SQLite transaction boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets


SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@+-]{2,63}$")


def normalize_username(value: str) -> str:
    username = value.strip().casefold()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3-64 characters using letters, digits, dot, underscore, @, +, or hyphen.")
    return username


def validate_password(value: str) -> None:
    if not isinstance(value, str) or len(value) < 15:
        raise ValueError("Password must contain at least 15 characters.")
    if len(value) > 1024 or "\x00" in value:
        raise ValueError("Password is too long or contains an unsupported character.")


def hash_password(password: str) -> str:
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    encode = lambda data: base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${encode(salt)}${encode(digest)}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not isinstance(password, str) or not encoded:
        return False
    try:
        scheme, raw_n, raw_r, raw_p, raw_salt, raw_digest = encoded.split("$", 5)
        n, r, p = int(raw_n), int(raw_r), int(raw_p)
        if scheme != "scrypt" or n < (1 << 14) or n > (1 << 17) or n & (n - 1):
            return False
        if not (1 <= r <= 16 and 1 <= p <= 4):
            return False
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        salt, expected = decode(raw_salt), decode(raw_digest)
        if len(salt) < 16 or len(expected) != SCRYPT_DKLEN:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            dklen=len(expected), maxmem=256 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError, MemoryError):
        return False


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)
