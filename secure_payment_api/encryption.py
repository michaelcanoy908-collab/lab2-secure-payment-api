"""
encryption.py
-------------
Fernet (AES-128-CBC) symmetric encryption utility.
The key is read from settings.FERNET_KEY (a base64-urlsafe 32-byte key).
"""

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
import logging

logger = logging.getLogger("security")


def _get_cipher() -> Fernet:
    """Return a Fernet cipher initialised with the project key."""
    key = getattr(settings, "FERNET_KEY", None)
    if not key:
        raise RuntimeError(
            "FERNET_KEY is not set in settings.  "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string and return a base64 token (str)."""
    cipher = _get_cipher()
    token = cipher.encrypt(plaintext.encode("utf-8"))
    logger.debug("Data encrypted successfully.")
    return token.decode("utf-8")


def decrypt(token: str) -> str:
    """Decrypt a Fernet token and return the original plaintext string.

    Raises ValueError for invalid / tampered tokens.
    """
    cipher = _get_cipher()
    try:
        plaintext = cipher.decrypt(token.encode("utf-8") if isinstance(token, str) else token)
        logger.debug("Data decrypted successfully.")
        return plaintext.decode("utf-8")
    except InvalidToken:
        logger.warning("Attempted decryption with an INVALID token — possible tampering detected.")
        raise ValueError("Invalid or tampered encrypted payload.")