import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.config import Settings
from app.db_init import initialize_database


def test_default_settings_use_postgresql():
    settings = Settings(_env_file=None)
    assert settings.DATABASE_URL.startswith("postgresql")


@pytest.mark.asyncio
async def test_initialize_database_creates_tables_idempotently(tmp_path):
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"

    await initialize_database(database_url=database_url)
    await initialize_database(database_url=database_url)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        result = await connection.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = {row[0] for row in result.fetchall()}

        assert "users" in tables
        assert "projects" in tables


def test_health_reports_database_readiness(tmp_path):
    db_path = tmp_path / "health.db"
    main.settings.DATABASE_URL = f"sqlite+aiosqlite:///{db_path}"

    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["database"]["status"] == "ready"
