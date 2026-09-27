"""Authentication utilities: JWT handling, password hashing, distributed revocation,
account lockout protection, and authorization guards.
"""

from datetime import UTC, datetime, timedelta
import hashlib
import logging
import os
import re
import uuid

import jwt
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import redis
from sqlalchemy.orm import Session

from .models import Project, Role, User, get_db

logger = logging.getLogger("intellivapt.auth")

# ---------------------------------------------------------------------------
# Configuration & Password Hashing
# ---------------------------------------------------------------------------

hasher = PasswordHasher()
bearer = HTTPBearer(auto_error=True)

# Secret management
SECRET = os.getenv("JWT_SECRET", "development-secret-change-me")
if SECRET == "development-secret-change-me":
    logger.warning(
        "SECURITY NOTICE: Default development JWT_SECRET is active. "
        "Define a strong, unpredictable JWT_SECRET in production environments."
    )

# Redis client for distributed token revocation and rate limiting / lockout
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_client: redis.Redis | None | bool = None

def get_redis_client() -> redis.Redis | None:
    """Return active Redis connection or None if unavailable."""
    global _redis_client
    if _redis_client is None:
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
            client.ping()
            _redis_client = client
        except Exception as e:
            logger.warning("Redis unavailable for auth cache: %s. Using in-memory fallback.", e)
            _redis_client = False
    return _redis_client if isinstance(_redis_client, redis.Redis) else None


# Fallback in-memory structures if Redis is offline
TOKEN_BLOCKLIST: set[str] = set()
IN_MEMORY_FAILED_LOGINS: dict[str, list[datetime]] = {}
IN_MEMORY_LOCKOUTS: dict[str, datetime] = {}
USER_REVOCATIONS: dict[str, float] = {}

# Constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes
COMMON_WEAK_PASSWORDS = {
    "password123!", "admin123456!", "qwerty12345!", "welcome1234!",
    "letmein1234!", "changeme1234!", "security1234!", "intellivapt123!"
}


# ---------------------------------------------------------------------------
# Password Validation (OWASP / NIST Standards)
# ---------------------------------------------------------------------------

def validate_password_strength(password: str, user_info: list[str] | None = None) -> None:
    """Validate password against rigorous complexity and entropy rules.

    Rules:
    - 12 to 128 characters long
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special symbol
    - No whitespace
    - Not on common weak password blacklist
    - Does not contain user personal info (e.g. name or username)
    """
    if len(password) < 12:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must be at least 12 characters long")
    if len(password) > 128:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must not exceed 128 characters")
    if re.search(r"\s", password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must not contain whitespace characters")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must include at least one uppercase letter (A-Z)")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must include at least one lowercase letter (a-z)")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password must include at least one digit (0-9)")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Password must include at least one special symbol (!@#$%^&*...)",
        )

    lower_pw = password.lower()
    if lower_pw in COMMON_WEAK_PASSWORDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Password is too common; choose a more secure passphrase")

    if user_info:
        for info in user_info:
            if info and len(info) >= 3 and info.lower() in lower_pw:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "Password must not contain parts of your name, email, or username",
                )


# ---------------------------------------------------------------------------
# Account Lockout Protection (Brute Force Defense)
# ---------------------------------------------------------------------------

def is_account_locked(email: str) -> bool:
    """Check if account is temporarily locked due to excessive failed attempts."""
    email_key = email.lower().strip()
    r = get_redis_client()
    if r:
        try:
            return bool(r.get(f"auth:lockout:{email_key}"))
        except Exception:
            pass

    # In-memory fallback
    locked_until = IN_MEMORY_LOCKOUTS.get(email_key)
    if locked_until:
        if datetime.now(UTC) < locked_until:
            return True
        del IN_MEMORY_LOCKOUTS[email_key]
    return False


def record_login_failure(email: str) -> tuple[int, bool]:
    """Record a failed login attempt and return (attempt_count, is_now_locked)."""
    email_key = email.lower().strip()
    r = get_redis_client()
    if r:
        try:
            fails_key = f"auth:fails:{email_key}"
            count = r.incr(fails_key)
            if count == 1:
                r.expire(fails_key, LOCKOUT_DURATION_SECONDS)
            if count >= MAX_LOGIN_ATTEMPTS:
                r.setex(f"auth:lockout:{email_key}", LOCKOUT_DURATION_SECONDS, "1")
                return count, True
            return count, False
        except Exception:
            pass

    # In-memory fallback
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=LOCKOUT_DURATION_SECONDS)
    attempts = [t for t in IN_MEMORY_FAILED_LOGINS.get(email_key, []) if t > cutoff]
    attempts.append(now)
    IN_MEMORY_FAILED_LOGINS[email_key] = attempts

    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        IN_MEMORY_LOCKOUTS[email_key] = now + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
        return len(attempts), True
    return len(attempts), False


def record_login_success(email: str) -> None:
    """Clear failed login attempts counter upon successful authentication."""
    email_key = email.lower().strip()
    r = get_redis_client()
    if r:
        try:
            r.delete(f"auth:fails:{email_key}", f"auth:lockout:{email_key}")
        except Exception:
            pass

    IN_MEMORY_FAILED_LOGINS.pop(email_key, None)
    IN_MEMORY_LOCKOUTS.pop(email_key, None)


# ---------------------------------------------------------------------------
# Token Revocation & Management
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    """Compute SHA-256 fingerprint of token for compact, secure storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def revoke_token(token: str) -> None:
    """Add a JWT token to the distributed revocation blocklist."""
    token_hash = _hash_token(token)
    r = get_redis_client()
    if r:
        try:
            # Block for default 8 hours (28800s)
            r.setex(f"auth:revoked:{token_hash}", 28800, "1")
        except Exception as e:
            logger.warning("Redis token revocation error: %s", e)

    # Always write to memory as secondary guard
    TOKEN_BLOCKLIST.add(token_hash)


def revoke_all_user_tokens(user_id: str) -> None:
    """Invalidate all existing tokens issued for a specific user."""
    now_ts = datetime.now(UTC).timestamp()
    r = get_redis_client()
    if r:
        try:
            r.setex(f"auth:user_revoked_before:{user_id}", 28800, str(now_ts))
        except Exception:
            pass
    USER_REVOCATIONS[user_id] = now_ts


def is_token_revoked(token: str, user_id: str | None = None, token_iat: float | None = None) -> bool:
    """Check if token or user session is in revocation blocklist."""
    token_hash = _hash_token(token)

    # 1. Check exact token hash
    if token_hash in TOKEN_BLOCKLIST:
        return True

    r = get_redis_client()
    if r:
        try:
            if r.get(f"auth:revoked:{token_hash}"):
                return True
            if user_id and token_iat is not None:
                revoked_before = r.get(f"auth:user_revoked_before:{user_id}")
                if revoked_before and token_iat < float(revoked_before):
                    return True
        except Exception:
            pass

    # 2. Check user-wide revocation in memory
    if user_id and token_iat is not None:
        user_revoked_at = USER_REVOCATIONS.get(user_id)
        if user_revoked_at and token_iat < user_revoked_at:
            return True

    return False


# ---------------------------------------------------------------------------
# Token Generation
# ---------------------------------------------------------------------------

def token_for(user: User, expires_in_hours: int = 8) -> str:
    """Create a cryptographically signed JWT access token for the given user."""
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": user.id,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "iat": now.timestamp(),
        "exp": now + timedelta(hours=expires_in_hours),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# FastAPI Dependencies & Access Guards
# ---------------------------------------------------------------------------

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    """Decode Bearer token, verify revocation state, and return the active user."""
    raw_token = credentials.credentials

    try:
        claims = jwt.decode(raw_token, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Access token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid access token signature")

    user_id = claims.get("sub")
    token_iat = claims.get("iat")

    if is_token_revoked(raw_token, user_id=user_id, token_iat=token_iat):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Access token has been revoked")

    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is disabled or unavailable")

    return user


def require(*roles: Role):
    """Enforce that the caller holds one of the specified roles."""
    def check(user: User = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role privileges for this operation")
        return user
    return check


def verify_project_access(project: Project | None, user: User, action: str = "access") -> None:
    """Enforce Object-Level Authorization (IDOR / BOLA Prevention).

    Only Administrators or the Project Owner can access or mutate project deliverables.
    """
    if not project:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")

    if user.role == Role.ADMIN:
        return

    if project.owner_id != user.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"You do not have permission to {action} this project",
        )
