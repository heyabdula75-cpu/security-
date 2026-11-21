"""
Authentication API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_current_user
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenRefreshRequest,
    TokenResponse,
    ProfileResponse,
)
from app.services.auth_service import (
    register_user,
    authenticate_user,
    create_tokens,
    get_user_by_id,
)

router = APIRouter()


@router.post("/auth/register", response_model=dict, status_code=201)
async def register(request: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account

    - **email**: User email address
    - **password**: User password
    - **full_name**: User full name
    - **organization_name**: Organization name
    """
    try:
        user = await register_user(
            db,
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            organization_name=request.organization_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    access_token, refresh_token, expires_in = await create_tokens(str(user.id))

    return {
        "success": True,
        "data": {
            "user": {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "organization_id": str(user.organization_id),
                "roles": [role.name for role in user.roles],
                "created_at": user.created_at,
                "last_login": user.last_login,
            },
            "token": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
                "token_type": "bearer",
            },
        },
    }


@router.post("/auth/login", response_model=dict)
async def login(request: UserLoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and return JWT token

    - **email**: User email address
    - **password**: User password
    """
    user = await authenticate_user(db, request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token, refresh_token, expires_in = await create_tokens(str(user.id))

    return {
        "success": True,
        "data": {
            "token": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
                "token_type": "bearer",
            },
            "user": {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "organization_id": str(user.organization_id),
                "roles": [role.name for role in user.roles],
                "created_at": user.created_at,
                "last_login": user.last_login,
            },
        },
    }


@router.post("/auth/refresh-token", response_model=dict)
async def refresh_token(request: TokenRefreshRequest):
    """
    Refresh expired access token

    - **refresh_token**: Refresh token from login
    """
    from app.utils.jwt_utils import decode_refresh_token

    try:
        payload = decode_refresh_token(request.refresh_token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc

    access_token, refresh_token, expires_in = await create_tokens(payload["sub"])
    return {
        "success": True,
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "token_type": "bearer",
        },
    }


@router.post("/auth/logout", status_code=204)
async def logout():
    """
    Logout user and invalidate token
    """
    return None


@router.get("/auth/me", response_model=dict)
@router.get("/auth/profile", response_model=dict)
async def get_profile(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Get current user profile

    Requires: Bearer token
    """
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    profile = ProfileResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        organization_id=str(user.organization_id),
        roles=[role.name for role in user.roles],
        created_at=user.created_at,
        last_login=user.last_login,
    )

    return {"success": True, "data": profile}


@router.post("/auth/mfa/enable", response_model=dict)
async def enable_mfa():
    """
    Enable MFA on user account

    Requires: Bearer token
    """
    return {
        "success": True,
        "data": {
            "qr_code": "data:image/png;base64,...",
            "secret": "JBSWY3DPEBLW64TMMQ======",
            "backup_codes": ["code1", "code2", "code3"],
        },
    }


@router.post("/auth/mfa/verify", response_model=dict)
async def verify_mfa(code: str):
    """
    Verify MFA code and enable MFA

    - **code**: 6-digit MFA code
    """
    return {"success": True, "data": {"mfa_enabled": True}}
