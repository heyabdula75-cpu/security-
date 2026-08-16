import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Component, ComponentVulnerability, Organization, Project, Sbom, Vulnerability
from app.services.risk_service import calculate_sbom_risk, get_component_recommendations


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
async def seeded_sbom(session: AsyncSession):
    organization = Organization(name="Risk Lab")
    session.add(organization)
    await session.flush()

    project = Project(
        organization_id=organization.id,
        name="Risk Project",
        slug="risk-project",
        description="Risk project",
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
        risk_score=0,
    )
    session.add(sbom)
    await session.flush()

    component = Component(
        sbom_id=sbom.id,
        name="log4j-core",
        version="2.14.0",
        type="library",
        purl="pkg:maven/log4j-core@2.14.0",
    )
    session.add(component)
    await session.flush()

    vulnerability = Vulnerability(
        cve_id="CVE-2021-44228",
        severity="critical",
        cvss_v3_score=10.0,
        description="Critical vulnerability",
        metadata_={"recommendation": "Upgrade to 2.17.1"},
    )
    session.add(vulnerability)
    await session.flush()

    session.add(ComponentVulnerability(component_id=component.id, vulnerability_id=vulnerability.id))
    await session.commit()
    return sbom, component


async def test_calculate_sbom_risk(session: AsyncSession, seeded_sbom):
    sbom, _ = seeded_sbom

    risk = await calculate_sbom_risk(session, str(sbom.id))

    assert risk["overall_score"] >= 90
    assert risk["critical_count"] == 1
    assert risk["threat_count"] >= 1


async def test_get_component_recommendations(session: AsyncSession, seeded_sbom):
    _, component = seeded_sbom

    recommendations = await get_component_recommendations(session, str(component.id))

    assert len(recommendations) >= 1
    assert recommendations[0]["priority"] in {"critical", "high", "medium", "low"}
