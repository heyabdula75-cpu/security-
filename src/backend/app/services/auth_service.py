"""Authentication service helpers with eager-loaded roles for async SQLAlchemy."""
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models import Organization, Role, User
from app.utils.jwt_utils import create_access_token, create_refresh_token
from app.utils.password_utils import get_password_hash, verify_password
from app.utils.time_utils import utcnow


def _as_uuid(value: str | UUID) -> UUID | str:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError:
        return str(value)


async def get_user_by_email(session: AsyncSession, email: str) -> Optional[User]:
    statement = select(User).options(selectinload(User.roles)).where(User.email == email)
    result = await session.execute(statement)
    return result.scalars().first()


async def get_user_by_id(session: AsyncSession, user_id: str | UUID) -> Optional[User]:
    statement = select(User).options(selectinload(User.roles)).where(User.id == _as_uuid(user_id))
    result = await session.execute(statement)
    return result.scalars().first()


async def get_or_create_organization(session: AsyncSession, organization_name: str) -> Organization:
    statement = select(Organization).where(Organization.name == organization_name)
    result = await session.execute(statement)
    organization = result.scalars().first()
    if organization:
        return organization

    organization = Organization(name=organization_name)
    session.add(organization)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        result = await session.execute(statement)
        organization = result.scalars().first()
        if organization:
            return organization
        raise

    return organization


async def get_or_create_role(session: AsyncSession, role_name: str = "user") -> Role:
    statement = select(Role).where(Role.name == role_name)
    result = await session.execute(statement)
    role = result.scalars().first()
    if role:
        return role

    role = Role(name=role_name, description=f"Default {role_name} role")
    session.add(role)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        result = await session.execute(statement)
        role = result.scalars().first()
        if role:
            return role
        raise

    return role


async def register_user(
    session: AsyncSession,
    email: str,
    password: str,
    full_name: str,
    organization_name: str,
) -> User:
    existing_user = await get_user_by_email(session, email)
    if existing_user:
        raise ValueError("A user with this email already exists.")

    organization = await get_or_create_organization(session, organization_name)
    role = await get_or_create_role(session, "user")

    user = User(
        email=email,
        password_hash=get_password_hash(password),
        full_name=full_name,
        organization=organization,
        is_active=True,
    )
    user.roles.append(role)
    session.add(user)
    await session.commit()
    return await get_user_by_id(session, user.id)


async def authenticate_user(session: AsyncSession, email: str, password: str) -> Optional[User]:
    user = await get_user_by_email(session, email)
    if not user or not verify_password(password, user.password_hash):
        return None

    user.last_login = utcnow().replace(tzinfo=None)
    await session.commit()
    return await get_user_by_id(session, user.id)


async def create_tokens(user_id: str) -> tuple[str, str, int]:
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return access_token, refresh_token, expires_in
