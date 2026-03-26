"""
utils/crypto.py — Fernet (AES-128-CBC + HMAC) encryption helpers
for stored site passwords.
"""

from cryptography.fernet import Fernet, InvalidToken
import config


def _get_fernet() -> Fernet:
    """
    Build and return a Fernet cipher instance using the key from config.
    Raises RuntimeError if FERNET_KEY is missing or invalid.
    """
    key = config.FERNET_KEY
    if not key:
        raise RuntimeError(
            "FERNET_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode("utf-8") if isinstance(key, str) else key)


def encrypt_password(plain: str) -> str:
    """
    Encrypt a plain-text password with Fernet (AES-128-CBC + HMAC-SHA256).
    Returns a URL-safe base64 string suitable for database storage.
    """
    f = _get_fernet()
    token = f.encrypt(plain.encode("utf-8"))
    # token is already bytes; decode to str for DB storage
    return token.decode("utf-8")


def decrypt_password(encrypted: str) -> str:
    """
    Decrypt a Fernet-encrypted password back to plain text.
    Raises cryptography.fernet.InvalidToken if the data is tampered or
    the wrong key is used.
    """
    f = _get_fernet()
    plain = f.decrypt(encrypted.encode("utf-8"))
    return plain.decode("utf-8")
