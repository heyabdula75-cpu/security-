"""
Tests for Production Enterprise Hardening (Steps 1-4):
- Dual JWT + X-API-Key authentication middleware
- Continuous zero-day rescan cycle
- Kubernetes runtime vs. signed CI/CD SBOM drift detection
- Security & rate-limit response headers
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.main import app
from app.middleware.auth import get_current_user
from app.models import Base, Organization, Project
from app.services.enterprise_service import create_api_key, sign_sbom
from app.services.monitor_service import evaluate_k8s_runtime_drift, run_continuous_rescan_cycle
from app.services.sbom_service import create_sbom


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as db_session:
        yield db_session

    await engine.dispose()


async def test_x_api_key_authentication_middleware(session: AsyncSession):
    org = Organization(name="CI Org")
    session.add(org)
    await session.commit()

    _, raw_key = await create_api_key(session, org.id, None, "CLI Pipeline", ["scan:write", "sbom:read"])
    principal = await get_current_user(credentials=None, x_api_key=raw_key, db=session)
    assert principal["auth_type"] == "api_key"
    assert principal["organization_id"] == str(org.id)
    assert "scan:write" in principal["scopes"]


async def test_continuous_rescan_and_k8s_runtime_drift(session: AsyncSession):
    org = Organization(name="Cloud Native Corp")
    session.add(org)
    await session.flush()

    proj = Project(organization_id=org.id, name="K8s Fleet", slug="k8s-fleet")
    session.add(proj)
    await session.commit()

    sbom = await create_sbom(
        session,
        str(proj.id),
        "dockerfile",
        "1.0",
        {},
        components_data=[
            {"name": "python", "version": "3.12-slim", "type": "container", "purl": "pkg:oci/python@3.12-slim"},
            {"name": "log4j-core", "version": "2.14.0", "type": "library", "purl": "pkg:maven/log4j-core@2.14.0"},
        ],
    )
    await sign_sbom(session, sbom.id, org.id, signer="ci-bot@cloud.io", slsa_level="SLSA_BUILD_L3")

    # 1. Continuous rescan monitor
    rescan = await run_continuous_rescan_cycle(session, org.id, use_live_osv=False)
    assert rescan["sboms_rescanned"] == 1
    assert rescan["active_kev_findings"] == 1

    # 2. K8s runtime drift: 1 verified signed, 1 version drift, 1 untracked shadow container
    drift = await evaluate_k8s_runtime_drift(
        session,
        org.id,
        workloads=[
            {"namespace": "prod", "pod": "api-1", "image": "python:3.12-slim"},
            {"namespace": "prod", "pod": "api-legacy", "image": "python:3.9-alpine"},
            {"namespace": "prod", "pod": "crypto-miner", "image": "rogue/miner:latest"},
        ],
    )
    assert drift["total_workloads"] == 3
    assert drift["verified_signed"] == 1
    assert drift["drifted_or_unsigned"] == 1
    assert drift["untracked_shadow"] == 1


def test_enterprise_security_and_rate_limit_headers():
    client = TestClient(app)
    resp = client.get("/api")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "X-RateLimit-Remaining" in resp.headers
