import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, Project
from app.services.project_service import create_project, delete_project, get_project, update_project


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
async def seeded_organization(session: AsyncSession):
    organization = Organization(name="Project Lab")
    session.add(organization)
    await session.commit()
    return organization


async def test_update_project_changes_name_and_slug(session: AsyncSession, seeded_organization):
    project = await create_project(
        session,
        str(seeded_organization.id),
        "Initial Name",
        description="Initial description",
    )

    updated_project = await update_project(
        session,
        str(project.id),
        name="Updated Name",
        description="Updated description",
    )

    assert updated_project is not None
    assert updated_project.name == "Updated Name"
    assert updated_project.slug == "updated-name"
    assert updated_project.description == "Updated description"


async def test_delete_project_removes_it(session: AsyncSession, seeded_organization):
    project = await create_project(session, str(seeded_organization.id), "Delete Me")

    deleted = await delete_project(session, str(project.id))
    fetched = await get_project(session, str(project.id), str(seeded_organization.id))

    assert deleted is True
    assert fetched is None
