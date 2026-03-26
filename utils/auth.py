"""
utils/auth.py — Password hashing and JWT token helpers
"""

import bcrypt
import jwt
import datetime
import config


# ── Password Hashing (bcrypt) ────────────────────────────────

def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password with bcrypt.
    Returns the hash as a UTF-8 string for storage.
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Check a plain-text password against a stored bcrypt hash.
    Returns True if they match, False otherwise.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


# ── JWT Tokens ───────────────────────────────────────────────

def generate_token(user_id: int, username: str, session_id: str = "") -> str:
    """
    Create a signed JWT containing user_id, username, and optional session_id.
    Token expires after JWT_EXPIRY_HOURS (from config).
    """
    payload = {
        "user_id":    user_id,
        "username":   username,
        "session_id": session_id,
        "exp": datetime.datetime.utcnow()
               + datetime.timedelta(hours=config.JWT_EXPIRY_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm="HS256")
    return token


def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT.
    Returns the payload dict on success.
    Raises jwt.ExpiredSignatureError if expired.
    Raises jwt.InvalidTokenError for any other problem.
    """
    payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=["HS256"])
    return payload
