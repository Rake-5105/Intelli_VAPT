"""Authentication utilities: JWT handling, password hashing, and dependency guards."""

import os
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .models import Role, User, get_db

# ---------------------------------------------------------------------------
# Configuration & Blocklist
# ---------------------------------------------------------------------------

hasher = PasswordHasher()
bearer = HTTPBearer()
SECRET = os.getenv("JWT_SECRET", "development-secret-change-me")
TOKEN_BLOCKLIST: set[str] = set()


def revoke_token(token: str) -> None:
    """Add a JWT token to the revocation blocklist."""
    TOKEN_BLOCKLIST.add(token)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def token_for(user: User, expires_in_hours: int = 8) -> str:
    """Create a JWT access token for the given user."""
    return jwt.encode(
        {
            "sub": user.id,
            "role": user.role.value if hasattr(user.role, "value") else str(user.role),
            "exp": datetime.now(UTC) + timedelta(hours=expires_in_hours),
        },
        SECRET,
        algorithm="HS256",
    )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    """Decode the Bearer token and return the active user, or raise 401/403."""
    raw_token = credentials.credentials
    if raw_token in TOKEN_BLOCKLIST:
        raise HTTPException(401, "Token has been revoked")

    try:
        claims = jwt.decode(raw_token, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired access token")

    user = db.get(User, claims.get("sub"))
    if not user or not user.active:
        raise HTTPException(403, "Account is unavailable")
    return user


def require(*roles: Role):
    """Return a dependency that enforces the caller has one of the given roles."""
    def check(user: User = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(403, "Insufficient permission")
        return user
    return check

