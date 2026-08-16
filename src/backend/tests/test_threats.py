from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, Project, Sbom
from app.services.threat_service import build_threats_for_sbom, list_threats_for_organization


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as db_session:
        yield db_session

    await engine.dispose()


@pytest.fixture
async def seeded_project(session: AsyncSession):
    organization = Organization(name="Threat Lab")
    session.add(organization)
    await session.flush()

    project = Project(
        organization_id=organization.id,
        name="Threat Project",
        slug="threat-project",
        description="Threat project",
    )
    session.add(project)
    await session.flush()

    sbom = Sbom(
        project_id=project.id,
        format="cyclonedx-json",
        version="1.5",
        content={"source": "github"},
        component_count=2,
        vulnerability_count=1,
        risk_score=95,
    )
    session.add(sbom)
    await session.commit()
    return organization, project, sbom


async def test_build_threats_for_sbom(session: AsyncSession, seeded_project):
    _, _, sbom = seeded_project

    threats = await build_threats_for_sbom(session, sbom.id, ["supply-chain", "dependency"])

    assert len(threats) >= 1
    assert threats[0]["status"] == "open"
    assert threats[0]["severity"] in {"high", "medium", "critical"}


async def test_list_threats_for_organization(session: AsyncSession, seeded_project):
    organization, _, sbom = seeded_project

    await build_threats_for_sbom(session, sbom.id, ["supply-chain"])
    threats = await list_threats_for_organization(session, organization.id)

    assert len(threats) >= 1
