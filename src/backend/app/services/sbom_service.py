"""SBOM service helpers."""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Sbom, Component, Project


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


async def create_sbom(
    session: AsyncSession,
    project_id: str,
    sbom_format: str,
    version: str | None,
    content: dict,
    components_data: list[dict] | None = None,
) -> Sbom:
    project_uuid = _as_uuid(project_id)
    sbom = Sbom(
        project_id=project_uuid,
        format=sbom_format,
        version=version or "1.0",
        content=content,
        component_count=len(components_data or []),
        vulnerability_count=0,
        risk_score=0,
    )
    session.add(sbom)
    await session.flush()

    components_data = components_data or []
    component_records = []
    for component_data in components_data:
        component = Component(
            sbom_id=sbom.id,
            name=component_data.get("name", "unknown"),
            version=component_data.get("version", "0.0.0"),
            type=component_data.get("type", "library"),
            purl=component_data.get("purl"),
            license=component_data.get("license"),
            author=component_data.get("author"),
            metadata_=component_data.get("metadata"),
        )
        session.add(component)
        component_records.append(component)

    await session.commit()
    await session.refresh(sbom)
    return sbom


async def list_sboms(session: AsyncSession, organization_id: str, limit: int = 20, offset: int = 0) -> list[Sbom]:
    organization_uuid = _as_uuid(organization_id)
    statement = (
        select(Sbom)
        .join(Project)
        .where(Project.organization_id == organization_uuid)
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(statement)
    return result.scalars().all()


async def get_sbom(session: AsyncSession, sbom_id: str, organization_id: str) -> Sbom | None:
    sbom_uuid = _as_uuid(sbom_id)
    organization_uuid = _as_uuid(organization_id)
    statement = (
        select(Sbom)
        .join(Project)
        .where(Sbom.id == sbom_uuid, Project.organization_id == organization_uuid)
    )
    result = await session.execute(statement)
    return result.scalars().first()


async def list_components(session: AsyncSession, sbom_id: str, limit: int = 20, offset: int = 0) -> list[Component]:
    sbom_uuid = _as_uuid(sbom_id)
    statement = select(Component).where(Component.sbom_id == sbom_uuid).limit(limit).offset(offset)
    result = await session.execute(statement)
    return result.scalars().all()


async def get_component(session: AsyncSession, component_id: str) -> Component | None:
    component_uuid = _as_uuid(component_id)
    statement = select(Component).where(Component.id == component_uuid)
    result = await session.execute(statement)
    return result.scalars().first()


async def get_project_by_id(session: AsyncSession, project_id: str) -> Project | None:
    project_uuid = _as_uuid(project_id)
    statement = select(Project).where(Project.id == project_uuid)
    result = await session.execute(statement)
    return result.scalars().first()
