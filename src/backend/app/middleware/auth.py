"""
Authentication middleware for FastAPI.
Supports both JWT Bearer tokens (Web UI / Users) and SHA-256 hashed X-API-Key headers (CLI / CI/CD).
"""
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User
from app.utils.jwt_utils import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # 1. X-API-Key authentication for CLI / CI/CD pipelines
    if x_api_key:
        from app.services.enterprise_service import verify_api_key

        api_key_record = await verify_api_key(db, x_api_key)
        if not api_key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API key",
            )
        return {
            "sub": str(api_key_record.user_id) if api_key_record.user_id else str(api_key_record.id),
            "organization_id": str(api_key_record.organization_id),
            "auth_type": "api_key",
            "api_key_id": str(api_key_record.id),
            "scopes": api_key_record.scopes or [],
        }

    # 2. JWT Bearer authentication for Web UI & interactive users
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header or X-API-Key missing",
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

    if "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    payload.setdefault("auth_type", "jwt")
    if not payload.get("organization_id"):
        from app.services.auth_service import get_user_by_id

        user = await get_user_by_id(db, payload["sub"])
        if user and user.organization_id:
            payload["organization_id"] = str(user.organization_id)
            payload.setdefault("email", user.email)
    return payload


async def get_current_active_user(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    user_id = current_user["sub"]
    statement = select(User).where(User.id == user_id)
    result = await db.execute(statement)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive or nonexistent user",
        )

    return user
