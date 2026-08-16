"""Project service helpers."""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Project


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def build_slug(name: str) -> str:
    return name.lower().strip().replace(" ", "-").replace("_", "-")


async def create_project(
    session: AsyncSession,
    organization_id: str,
    name: str,
    description: str | None = None,
    repository_url: str | None = None,
    repository_type: str | None = None,
) -> Project:
    slug = build_slug(name)
    organization_uuid = _as_uuid(organization_id)
    project = Project(
        organization_id=organization_uuid,
        name=name,
        slug=slug,
        description=description,
        repository_url=repository_url,
        repository_type=repository_type,
    )
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


async def list_projects(session: AsyncSession, organization_id: str, limit: int = 20, offset: int = 0) -> list[Project]:
    statement = (
        select(Project)
        .where(Project.organization_id == organization_id)
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(statement)
    return result.scalars().all()


async def get_project(session: AsyncSession, project_id: str, organization_id: str) -> Project | None:
    project_uuid = _as_uuid(project_id)
    organization_uuid = _as_uuid(organization_id)
    statement = select(Project).where(
        Project.id == project_uuid,
        Project.organization_id == organization_uuid,
    )
    result = await session.execute(statement)
    return result.scalars().first()


async def update_project(
    session: AsyncSession,
    project_id: str,
    name: str | None = None,
    description: str | None = None,
    repository_url: str | None = None,
    repository_type: str | None = None,
) -> Project | None:
    project_uuid = _as_uuid(project_id)
    statement = select(Project).where(Project.id == project_uuid)
    result = await session.execute(statement)
    project = result.scalars().first()
    if not project:
        return None

    if name is not None:
        project.name = name
        project.slug = build_slug(name)
    if description is not None:
        project.description = description
    if repository_url is not None:
        project.repository_url = repository_url
    if repository_type is not None:
        project.repository_type = repository_type

    await session.commit()
    await session.refresh(project)
    return project


async def delete_project(session: AsyncSession, project_id: str) -> bool:
    project_uuid = _as_uuid(project_id)
    statement = select(Project).where(Project.id == project_uuid)
    result = await session.execute(statement)
    project = result.scalars().first()
    if not project:
        return False

    await session.delete(project)
    await session.commit()
    return True
