"""
Authentication request and response schemas.
"""
from datetime import datetime
from pydantic import BaseModel, EmailStr


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    organization_name: str


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    organization_id: str
    roles: list[str]
    created_at: datetime
    last_login: datetime | None


class ProfileResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    organization_id: str
    roles: list[str]
    created_at: datetime
    last_login: datetime | None
