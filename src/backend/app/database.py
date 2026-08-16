"""
Database connection and session management.
"""
from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings


class DatabaseSessionManager:
    """Lazily create the async engine and session factory."""

    def __init__(self) -> None:
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[sessionmaker] = None

    def _get_engine(self) -> AsyncEngine:
        if self._engine is None:
            database_url = settings.DATABASE_URL
            if database_url.startswith("postgresql://") and "+asyncpg" not in database_url:
                database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

            engine_kwargs = {
                "echo": settings.DATABASE_ECHO,
                "future": True,
                "pool_pre_ping": True,
            }
            if database_url.startswith("sqlite"):
                engine_kwargs["connect_args"] = {"check_same_thread": False}
            else:
                engine_kwargs.update(
                    {
                        "pool_size": settings.DB_POOL_SIZE,
                        "max_overflow": settings.DB_MAX_OVERFLOW,
                        "pool_timeout": settings.DB_POOL_TIMEOUT,
                        "pool_recycle": settings.DB_POOL_RECYCLE,
                        "connect_args": {
                            "timeout": settings.DB_CONNECT_TIMEOUT,
                            "command_timeout": settings.DB_CONNECT_TIMEOUT,
                            "ssl": False if settings.DB_SSL_MODE == "disable" else settings.DB_SSL_MODE,
                        },
                    }
                )

            self._engine = create_async_engine(
                database_url,
                **engine_kwargs,
            )
        return self._engine

    def _get_session_factory(self) -> sessionmaker:
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self._get_engine(),
                class_=AsyncSession,
                expire_on_commit=False,
            )
        return self._session_factory


session_manager = DatabaseSessionManager()


async def get_db() -> AsyncIterator[AsyncSession]:
    """Yield a database session."""
    async_session = session_manager._get_session_factory()
    async with async_session() as session:
        yield session
