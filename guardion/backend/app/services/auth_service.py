"""
Guardion Authentication Service
Handles JWT token creation/verification and password hashing.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings
from app.db.mongodb import users_collection

# ──────────────────── Password Hashing ────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ──────────────────── JWT Tokens ────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload to encode (must include 'sub' for user identification).
        expires_delta: Custom expiration time. Defaults to JWT_EXPIRE_MINUTES.

    Returns:
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT token.

    Returns:
        Decoded payload dict.

    Raises:
        HTTPException 401 if token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ──────────────────── FastAPI Dependencies ────────────────────

security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    FastAPI dependency — extracts and validates the current user from JWT.
    Returns the full user document from MongoDB (minus password_hash).
    """
    payload = decode_access_token(credentials.credentials)
    user_email = payload.get("sub")
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = users_collection().find_one({"email": user_email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Return user dict without password hash, convert ObjectId to string
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    return user


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """
    FastAPI dependency — ensures the current user has admin role.
    Must be used after get_current_user.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
) -> Optional[dict]:
    """
    FastAPI dependency — returns user dict if valid token present,
    None otherwise. Use for endpoints that work with or without auth
    (e.g., Chrome extension before user logs in).
    """
    if credentials is None:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
        user_email = payload.get("sub")
        if not user_email:
            return None
        user = users_collection().find_one({"email": user_email})
        if not user:
            return None
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except Exception:
        return None