import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.models import Base

logger = logging.getLogger("app.db_init")

def _is_postgres(url: str) -> bool:
    return url.startswith("postgresql") or url.startswith("postgres")


def _is_mysql(url: str) -> bool:
    return url.startswith("mysql")


async def create_database_if_needed(database_url: Optional[str] = None) -> None:
    """Create the target database if it does not already exist.

    Supports MySQL and PostgreSQL. SQLite databases are created automatically
    by the engine so no action is needed.
    """
    url = database_url or ""
    if not url:
        from app.config import settings
        url = settings.DATABASE_URL

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    if _is_postgres(url):
        parsed = urlparse(url)
        db_name = parsed.path.lstrip("/") or "sbom_platform"
        # Connect to the built-in maintenance database to issue CREATE DATABASE
        admin_url = url[:url.rfind("/" + db_name)] + "/postgres"
        engine = create_async_engine(admin_url, future=True, isolation_level="AUTOCOMMIT")
        try:
            async with engine.connect() as conn:
                exists = await conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": db_name},
                )
                if not exists.scalar():
                    await conn.execute(text(f'CREATE DATABASE "{db_name}"'))
                    logger.info("PostgreSQL database '%s' created.", db_name)
                else:
                    logger.info("PostgreSQL database '%s' already exists.", db_name)
        finally:
            await engine.dispose()
        return

    # ── MySQL ────────────────────────────────────────────────────────────────
    if _is_mysql(url):
        parsed = urlparse(url)
        database_name = parsed.path.lstrip("/") or "sbom_platform"
        admin_url = url.replace(f"/{database_name}", "/mysql", 1)
        engine = create_async_engine(admin_url, future=True)
        async with engine.begin() as connection:
            await connection.execute(
                text(f"CREATE DATABASE IF NOT EXISTS `{database_name}`")
            )
        await engine.dispose()


async def initialize_database(
    database_url: Optional[str] = None, *, echo: bool = False
) -> AsyncEngine:
    """Create the database if needed and create all tables.

    Safe to run repeatedly — idempotent for all supported dialects.
    """
    url = database_url or ""
    if not url:
        from app.config import settings
        url = settings.DATABASE_URL

    await create_database_if_needed(url)

    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_async_engine(
        url,
        echo=echo,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    except Exception as exc:
        raise RuntimeError(f"Database initialization failed: {exc}") from exc

    return engine


async def initialize_database_from_settings(*, echo: bool = False) -> AsyncEngine:
    """Initialize the configured database from app settings."""
    from app.config import settings

    primary_url = settings.DATABASE_URL

    if primary_url.startswith("sqlite"):
        logger.info("Using SQLite database: %s", primary_url)
        return await initialize_database(primary_url, echo=echo)

    try:
        engine = await initialize_database(primary_url, echo=echo)
        dialect = "PostgreSQL" if _is_postgres(primary_url) else "MySQL"
        logger.info("Connected to %s: %s", dialect, primary_url.split("@")[-1])
        return engine
    except Exception as exc:
        logger.error("Failed to initialize primary database (%s): %s", primary_url, exc)
        raise RuntimeError(f"Database initialization failed: {exc}") from exc


async def get_database_readiness(database_url: Optional[str] = None) -> dict:
    """Lightweight health-check: returns dialect and connection status."""
    url = database_url or ""
    if not url:
        from app.config import settings
        url = settings.DATABASE_URL

    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_async_engine(
        url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        dialect = engine.dialect.name
        return {"status": "ready", "dialect": dialect}
    except Exception as exc:
        return {
            "status": "unavailable",
            "dialect": engine.dialect.name,
            "error": str(exc),
        }
    finally:
        await engine.dispose()


if __name__ == "__main__":
    try:
        asyncio.run(initialize_database_from_settings())
        print("Database initialization completed successfully")
    except Exception as exc:
        print(f"Database initialization failed: {exc}")
        raise SystemExit(1)
