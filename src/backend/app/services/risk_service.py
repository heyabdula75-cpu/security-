"""Contextual multi-factor risk scoring (CVSS + EPSS + CISA KEV + Supply Chain Threats) & remediation helpers."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Component, ComponentVulnerability, Sbom, ThreatDetection, Vulnerability
from app.utils.time_utils import utcnow_iso

SEVERITY_WEIGHTS = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def _grade_from_score(score: float) -> str:
    if score <= 15:
        return "A"
    if score <= 35:
        return "B"
    if score <= 55:
        return "C"
    if score <= 75:
        return "D"
    return "F"


async def calculate_sbom_risk(session: AsyncSession, sbom_id: str | UUID) -> dict:
    sbom_uuid = _as_uuid(sbom_id)
    statement = select(Sbom).where(Sbom.id == sbom_uuid)
    sbom = (await session.execute(statement)).scalars().first()
    if not sbom:
        return {
            "sbom_id": str(sbom_id),
            "overall_score": 0.0,
            "risk_grade": "A",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "kev_count": 0,
            "avg_epss": 0.0,
            "threat_count": 0,
            "remediable_count": 0,
            "calculated_at": utcnow_iso(),
        }

    vuln_id_subq = (
        select(Vulnerability.id)
        .join(ComponentVulnerability)
        .join(Component)
        .where(Component.sbom_id == sbom_uuid)
        .distinct()
    )
    vulnerabilities = (await session.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_id_subq)))).scalars().all()

    threat_stmt = select(ThreatDetection).where(
        ThreatDetection.sbom_id == sbom_uuid,
        ThreatDetection.status == "open",
    )
    open_threats = (await session.execute(threat_stmt)).scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kev_count = 0
    epss_values: list[float] = []
    remediable_count = 0
    vuln_scores: list[float] = []

    for vuln in vulnerabilities:
        sev = (vuln.severity or "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

        meta = vuln.metadata_ or {}
        in_kev = bool(meta.get("in_kev", False))
        if in_kev:
            kev_count += 1
        raw_epss = meta.get("epss_score")
        epss = float(raw_epss) if raw_epss is not None else None
        if epss is not None:
            epss_values.append(epss)
        if meta.get("fixed_version") or meta.get("recommendation"):
            remediable_count += 1

        base = (vuln.cvss_v3_score * 10.0) if vuln.cvss_v3_score is not None else float(SEVERITY_WEIGHTS.get(sev, 25))
        # Contextual weighting: do not penalize when EPSS is absent; boost for high EPSS & CISA KEV
        epss_factor = (0.90 + 0.15 * epss) if epss is not None else 1.0
        contextual = base * epss_factor + (12.0 if in_kev else 0.0)
        vuln_scores.append(min(100.0, contextual))

    threat_scores = [
        float(SEVERITY_WEIGHTS.get((t.severity or "medium").lower(), 50)) * t.confidence_score
        for t in open_threats
        if t.threat_type not in {"dependency"}
    ]

    all_signals = vuln_scores + threat_scores
    if all_signals:
        # Peak-weighted contextual score (70% worst exposure + 30% average exposure)
        overall_score = min(100.0, (0.7 * max(all_signals)) + (0.3 * (sum(all_signals) / len(all_signals))))
    else:
        overall_score = 0.0

    overall_score = round(overall_score, 1)
    avg_epss = round(sum(epss_values) / len(epss_values), 3) if epss_values else 0.0

    return {
        "sbom_id": str(sbom.id),
        "overall_score": overall_score,
        "risk_grade": _grade_from_score(overall_score),
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "kev_count": kev_count,
        "avg_epss": avg_epss,
        "threat_count": len(vulnerabilities) + len(open_threats),
        "open_supply_chain_threats": len(open_threats),
        "remediable_count": remediable_count or len(vulnerabilities),
        "calculated_at": utcnow_iso(),
    }


async def get_component_recommendations(session: AsyncSession, component_id: str | UUID) -> list[dict]:
    component_uuid = _as_uuid(component_id)
    component = (await session.execute(select(Component).where(Component.id == component_uuid))).scalars().first()
    if not component:
        return []

    vulns_stmt = (
        select(Vulnerability)
        .join(ComponentVulnerability)
        .where(ComponentVulnerability.component_id == component_uuid)
    )
    vulns = (await session.execute(vulns_stmt)).scalars().all()

    threats_stmt = select(ThreatDetection).where(
        ThreatDetection.component_id == component_uuid,
        ThreatDetection.status == "open",
    )
    threats = (await session.execute(threats_stmt)).scalars().all()

    recommendations: list[dict] = []

    for vuln in vulns:
        meta = vuln.metadata_ or {}
        fixed_version = meta.get("fixed_version")
        in_kev = bool(meta.get("in_kev", False))
        priority = "critical" if (in_kev or vuln.severity == "critical") else (vuln.severity or "medium")
        title = (
            f"URGENT (CISA KEV): Upgrade {component.name} to {fixed_version}"
            if in_kev and fixed_version
            else f"Upgrade {component.name} to {fixed_version} ({vuln.cve_id})"
            if fixed_version
            else f"Remediate {vuln.cve_id} in {component.name}"
        )
        recommendations.append(
            {
                "component_id": str(component.id),
                "cve_id": vuln.cve_id,
                "priority": priority,
                "in_kev": in_kev,
                "epss_score": meta.get("epss_score"),
                "fixed_version": fixed_version,
                "title": title,
                "description": meta.get("recommendation") or vuln.description or "Upgrade to a patched release.",
            }
        )

    for threat in threats:
        recommendations.append(
            {
                "component_id": str(component.id),
                "priority": threat.severity,
                "title": f"Investigate {threat.threat_type} alert on {component.name}",
                "description": threat.summary,
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "component_id": str(component.id),
                "priority": "low",
                "title": f"Monitor {component.name}@{component.version}",
                "description": "No active vulnerabilities or supply chain threats detected. Keep dependency pinned with hashes.",
            }
        )

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r["priority"], 4))
    return recommendations
