import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, Project
from app.services.sbom_service import create_sbom, get_sbom, get_component, list_components, list_sboms


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
    organization = Organization(name="Acme Corp")
    session.add(organization)
    await session.flush()

    project = Project(
        organization_id=organization.id,
        name="Demo Project",
        slug="demo-project",
        description="Demo project for SBOM tests",
    )
    session.add(project)
    await session.flush()

    await session.commit()
    return organization, project


async def test_create_and_retrieve_sbom(session: AsyncSession, seeded_project):
    organization, project = seeded_project

    sbom = await create_sbom(
        session,
        str(project.id),
        "cyclonedx-json",
        "1.5",
        {"source": "github", "repository_url": "https://example.com/demo"},
        components_data=[
            {
                "name": "requests",
                "version": "2.32.0",
                "type": "library",
                "purl": "pkg:pypi/requests@2.32.0",
            }
        ],
    )

    stored_sboms = await list_sboms(session, str(organization.id))
    fetched_sbom = await get_sbom(session, str(sbom.id), str(organization.id))

    assert len(stored_sboms) == 1
    assert fetched_sbom is not None
    assert fetched_sbom.component_count == 1
    assert fetched_sbom.vulnerability_count == 0


async def test_list_and_get_components(session: AsyncSession, seeded_project):
    _, project = seeded_project

    sbom = await create_sbom(
        session,
        str(project.id),
        "spdx-json",
        "2.3",
        {"source": "local"},
        components_data=[
            {
                "name": "fastapi",
                "version": "0.110.0",
                "type": "library",
                "purl": "pkg:pypi/fastapi@0.110.0",
            },
            {
                "name": "sqlalchemy",
                "version": "2.0.0",
                "type": "library",
                "purl": "pkg:pypi/sqlalchemy@2.0.0",
            },
        ],
    )

    components = await list_components(session, str(sbom.id))
    component = await get_component(session, str(components[0].id))

    assert len(components) == 2
    assert component is not None
    assert component.name == "fastapi"
