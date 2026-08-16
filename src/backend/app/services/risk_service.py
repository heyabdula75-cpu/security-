"""Risk scoring and remediation helpers."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Component, ComponentVulnerability, Sbom, Vulnerability
from app.utils.time_utils import utcnow_iso


SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


async def calculate_sbom_risk(session: AsyncSession, sbom_id: str | UUID) -> dict:
    sbom_uuid = _as_uuid(sbom_id)
    statement = select(Sbom).where(Sbom.id == sbom_uuid)
    result = await session.execute(statement)
    sbom = result.scalars().first()
    if not sbom:
        return {
            "sbom_id": str(sbom_id),
            "overall_score": 0.0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "threat_count": 0,
            "remediable_count": 0,
            "calculated_at": utcnow_iso(),
        }

    statement = (
        select(Vulnerability)
        .join(ComponentVulnerability)
        .join(Component)
        .where(Component.sbom_id == sbom_uuid)
        .distinct()
    )
    result = await session.execute(statement)
    vulnerabilities = result.scalars().all()

    severity_counts = {level: 0 for level in ["critical", "high", "medium", "low"]}
    for vulnerability in vulnerabilities:
        severity_counts[vulnerability.severity] = severity_counts.get(vulnerability.severity, 0) + 1

    overall_score = sum(SEVERITY_WEIGHTS.get(vulnerability.severity, 0) for vulnerability in vulnerabilities)
    overall_score = min(100.0, overall_score / max(1, len(vulnerabilities)))

    return {
        "sbom_id": str(sbom.id),
        "overall_score": round(overall_score, 1),
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "threat_count": len(vulnerabilities),
        "remediable_count": len(vulnerabilities),
        "calculated_at": utcnow_iso(),
    }


async def get_component_recommendations(session: AsyncSession, component_id: str | UUID) -> list[dict]:
    component_uuid = _as_uuid(component_id)
    statement = (
        select(Component)
        .where(Component.id == component_uuid)
    )
    result = await session.execute(statement)
    component = result.scalars().first()
    if not component:
        return []

    recommendations = []
    if component.name and "log4j" in component.name.lower():
        recommendations.append(
            {
                "component_id": str(component.id),
                "priority": "critical",
                "title": "Upgrade Log4j to a patched version",
                "description": "Replace the vulnerable Log4j package with a patched release such as 2.17.1 or later.",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "component_id": str(component.id),
                "priority": "medium",
                "title": "Review package version",
                "description": "Validate whether a newer, non-vulnerable version is available.",
            }
        )

    return recommendations
