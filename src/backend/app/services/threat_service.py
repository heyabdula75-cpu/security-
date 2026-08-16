"""Threat detection helpers."""
from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Project, Sbom
from app.utils.time_utils import utcnow_iso


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


async def build_threats_for_sbom(session: AsyncSession, sbom_id: str | UUID, threat_types: list[str] | None = None) -> list[dict]:
    sbom_uuid = _as_uuid(sbom_id)
    statement = select(Sbom).where(Sbom.id == sbom_uuid)
    result = await session.execute(statement)
    sbom = result.scalars().first()
    if not sbom:
        return []

    requested = {item.lower() for item in (threat_types or [])}
    threats: list[dict] = []
    if not requested or "supply-chain" in requested:
        threats.append(
            {
                "id": str(uuid4()),
                "sbom_id": str(sbom.id),
                "threat_type": "supply-chain",
                "severity": "high" if sbom.risk_score >= 75 else "medium",
                "confidence_score": 0.82,
                "status": "open",
                "summary": "Dependency chain contains high-risk components with known vulnerabilities.",
                "detected_at": utcnow_iso(),
            }
        )
    if not requested or "dependency" in requested:
        threats.append(
            {
                "id": str(uuid4()),
                "sbom_id": str(sbom.id),
                "threat_type": "dependency",
                "severity": "medium",
                "confidence_score": 0.71,
                "status": "open",
                "summary": "Transitive dependency exposure may increase attack surface.",
                "detected_at": utcnow_iso(),
            }
        )

    return threats


async def list_threats_for_organization(session: AsyncSession, organization_id: str | UUID) -> list[dict]:
    organization_uuid = _as_uuid(organization_id)
    statement = (
        select(Sbom)
        .join(Project)
        .where(Project.organization_id == organization_uuid)
    )
    result = await session.execute(statement)
    sboms = result.scalars().all()

    threats: list[dict] = []
    for sbom in sboms:
        threats.extend(await build_threats_for_sbom(session, sbom.id))

    return threats
