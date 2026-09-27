"""Authentication routes: register, login, logout, password change, and current user."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from ..audit import log_security_event
from ..auth import (
    bearer,
    current_user,
    hasher,
    is_account_locked,
    record_login_failure,
    record_login_success,
    revoke_all_user_tokens,
    revoke_token,
    token_for,
    validate_password_strength,
)
from ..middleware import limiter
from ..models import User, get_db
from ..schemas import AuthOut, ChangePassword, Login, Register, UserOut

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", status_code=201, response_model=AuthOut)
@limiter.limit("3/minute")
def register(request: Request, data: Register, db: Session = Depends(get_db)):
    """Register a new user account with strict password validation."""
    email_clean = data.email.lower().strip()
    name_clean = data.name.strip()

    # Enforce password complexity
    validate_password_strength(data.password, [name_clean, email_clean.split("@")[0]])

    if db.query(User).filter_by(email=email_clean).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email is already registered")

    user = User(
        name=name_clean,
        email=email_clean,
        password_hash=hasher.hash(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_security_event(
        db,
        action="USER_REGISTER",
        resource_type="user",
        resource_id=user.id,
        detail=f"User {user.email} registered with SECURITY_ANALYST role",
        user=user,
        request=request,
    )

    return {
        "access_token": token_for(user),
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.post("/login", response_model=AuthOut)
@limiter.limit("5/minute")
def login(request: Request, data: Login, db: Session = Depends(get_db)):
    """Authenticate with email and password with brute-force lockout defense."""
    email_clean = data.email.lower().strip()

    # 1. Check account lockout state
    if is_account_locked(email_clean):
        log_security_event(
            db,
            action="LOGIN_REJECTED_LOCKED",
            resource_type="auth",
            resource_id=email_clean,
            detail=f"Login attempt on locked account: {email_clean}",
            user_email=email_clean,
            request=request,
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Account is temporarily locked due to multiple consecutive failed attempts. "
            "Please try again after 15 minutes.",
        )

    # 2. Query user
    user = db.query(User).filter_by(email=email_clean).first()
    if not user or not user.active:
        count, is_locked = record_login_failure(email_clean)
        log_security_event(
            db,
            action="LOGIN_FAILED",
            resource_type="auth",
            resource_id=email_clean,
            detail=f"Failed login attempt for unknown/inactive email: {email_clean}",
            user_email=email_clean,
            request=request,
        )
        if is_locked:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Account is temporarily locked due to multiple consecutive failed attempts. Please try again after 15 minutes.",
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    # 3. Verify password
    try:
        if not hasher.verify(user.password_hash, data.password):
            count, is_locked = record_login_failure(email_clean)
            log_security_event(
                db,
                action="LOGIN_FAILED",
                resource_type="user",
                resource_id=user.id,
                detail=f"Failed password verification for user: {user.email}",
                user=user,
                request=request,
            )
            if is_locked:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Account is temporarily locked due to 5 failed attempts. Please try again after 15 minutes.",
                )
            remaining = max(0, 5 - count)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                f"Invalid credentials. ({remaining} attempt{'s' if remaining != 1 else ''} remaining before temporary lockout)",
            )
    except HTTPException:
        raise
    except Exception:
        record_login_failure(email_clean)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    # 4. Successful login
    record_login_success(email_clean)
    log_security_event(
        db,
        action="LOGIN_SUCCESS",
        resource_type="user",
        resource_id=user.id,
        detail=f"User {user.email} authenticated successfully",
        user=user,
        request=request,
    )

    return {
        "access_token": token_for(user),
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Revoke active JWT token and terminate server-side session."""
    raw_token = credentials.credentials
    revoke_token(raw_token)

    log_security_event(
        db,
        action="LOGOUT",
        resource_type="user",
        resource_id=user.id,
        detail=f"User {user.email} logged out and revoked session token",
        user=user,
        request=request,
    )


@router.post("/change-password", response_model=AuthOut)
@limiter.limit("5/minute")
def change_password(
    request: Request,
    data: ChangePassword,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Verify current password, enforce complexity on new password, and invalidate all prior sessions."""
    # Verify current password
    try:
        if not hasher.verify(user.password_hash, data.current_password):
            log_security_event(
                db,
                action="PASSWORD_CHANGE_FAILED",
                resource_type="user",
                resource_id=user.id,
                detail=f"Password change rejected: incorrect current password for {user.email}",
                user=user,
                request=request,
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")

    if data.new_password == data.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must be different from current password")

    # Enforce password strength
    validate_password_strength(data.new_password, [user.name, user.email.split("@")[0]])

    # Update hash
    user.password_hash = hasher.hash(data.new_password)
    db.commit()

    # Revoke all previous tokens across all devices
    revoke_all_user_tokens(user.id)

    log_security_event(
        db,
        action="PASSWORD_CHANGE_SUCCESS",
        resource_type="user",
        resource_id=user.id,
        detail=f"User {user.email} successfully updated password; all prior sessions invalidated",
        user=user,
        request=request,
    )

    # Return fresh token for current session
    return {
        "access_token": token_for(user),
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    """Return the currently authenticated user profile."""
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}
