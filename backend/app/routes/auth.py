"""Authentication routes: register, login, and current user."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..auth import current_user, hasher, token_for
from ..middleware import limiter
from ..models import User, get_db
from ..schemas import AuthOut, Login, Register, UserOut

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", status_code=201, response_model=AuthOut)
@limiter.limit("3/minute")
def register(request: Request, data: Register, db: Session = Depends(get_db)):
    """Register a new user account."""
    if db.query(User).filter_by(email=data.email.lower()).first():
        raise HTTPException(409, "Email is already registered")

    user = User(
        name=data.name,
        email=data.email.lower(),
        password_hash=hasher.hash(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "access_token": token_for(user),
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.post("/login", response_model=AuthOut)
@limiter.limit("5/minute")
def login(request: Request, data: Login, db: Session = Depends(get_db)):
    """Authenticate with email and password."""
    user = db.query(User).filter_by(email=data.email.lower()).first()
    if not user or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    try:
        if not hasher.verify(user.password_hash, data.password):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    return {
        "access_token": token_for(user),
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    """Return the currently authenticated user profile."""
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}
