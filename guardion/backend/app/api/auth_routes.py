"""
Guardion Auth Routes
POST /auth/signup  — register new user
POST /auth/login   — authenticate and return JWT
GET  /auth/me      — return current user info (protected)
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr, Field

from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)
from app.db.mongodb import users_collection

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ──────────────────── Request / Response Schemas ────────────────────

class SignupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str


# ──────────────────── Endpoints ────────────────────

@router.post("/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def signup(req: SignupRequest):
    """Register a new user account."""
    col = users_collection()

    # Check if email already exists
    if col.find_one({"email": req.email}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    now = datetime.now(timezone.utc)
    user_doc = {
        "name": req.name,
        "email": req.email,
        "password_hash": hash_password(req.password),
        "role": "client",  # default role
        "created_at": now,
        "updated_at": now,
    }

    result = col.insert_one(user_doc)
    user_id = str(result.inserted_id)

    token = create_access_token(data={"sub": req.email, "role": "client"})

    return AuthResponse(
        access_token=token,
        user={
            "id": user_id,
            "name": req.name,
            "email": req.email,
            "role": "client",
            "created_at": now.isoformat(),
        },
    )


@router.post("/login", response_model=AuthResponse)
def login(req: LoginRequest):
    """Authenticate user and return JWT token."""
    col = users_collection()
    user = col.find_one({"email": req.email})

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(data={"sub": user["email"], "role": user["role"]})

    return AuthResponse(
        access_token=token,
        user={
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"].isoformat() if user.get("created_at") else "",
        },
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return UserResponse(
        id=current_user["_id"],
        name=current_user["name"],
        email=current_user["email"],
        role=current_user["role"],
        created_at=(
            current_user["created_at"].isoformat()
            if isinstance(current_user.get("created_at"), datetime)
            else str(current_user.get("created_at", ""))
        ),
    )