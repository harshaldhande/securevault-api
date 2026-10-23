import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Return a salted Argon2id password hash."""
    return password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password without exposing verification errors."""
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_session_token() -> str:
    """Generate a cryptographically random opaque token."""
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Hash a session token before database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
