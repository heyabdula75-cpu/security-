"""
Automated Regulatory Compliance Evaluator:
Evaluates live SBOMs, vulnerabilities, CISA KEV exposure, VEX attestations,
and supply-chain threats against:
- EU Cyber Resilience Act (EU CRA)
- CISA 2026 Minimum Elements for SBOM
- US FDA Section 524B (Medical / Cyber Devices)
- EU AI Act (Annex IV / AI-BOM)
- NIST SP 800-218 (SSDF)
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Component,
    ComponentVulnerability,
    Project,
    Sbom,
    ThreatDetection,
    VexStatement,
    Vulnerability,
)
from app.services.sbom_parser import evaluate_sbom_completeness
from app.utils.time_utils import utcnow_iso


def _as_uuid(value: str | UUID) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


async def evaluate_organization_compliance(
    session: AsyncSession,
    organization_id: str | UUID,
    sbom_id: str | UUID | None = None,
) -> dict[str, Any]:
    """Run automated compliance checks across the organization (or a specific SBOM)."""
    org_uuid = _as_uuid(organization_id)

    sbom_query = (
        select(Sbom)
        .options(selectinload(Sbom.components))
        .join(Project)
        .where(Project.organization_id == org_uuid)
    )
    if sbom_id:
        sbom_query = sbom_query.where(Sbom.id == _as_uuid(sbom_id))

    sboms = (await session.execute(sbom_query)).scalars().all()
    sbom_ids = [s.id for s in sboms]

    all_components: list[Component] = [c for s in sboms for c in s.components]
    completeness_scores = [evaluate_sbom_completeness(s, list(s.components))["completeness_score"] for s in sboms]
    avg_completeness = round(sum(completeness_scores) / len(completeness_scores), 1) if completeness_scores else 0.0

    vulns: list[Vulnerability] = []
    open_threats: list[ThreatDetection] = []
    vex_statements: list[VexStatement] = []

    if sbom_ids:
        vuln_id_subq = (
            select(Vulnerability.id)
            .join(ComponentVulnerability)
            .join(Component)
            .where(Component.sbom_id.in_(sbom_ids))
            .distinct()
        )
        vulns = (
            await session.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_id_subq)))
        ).scalars().all()

        open_threats = (
            await session.execute(
                select(ThreatDetection).where(
                    ThreatDetection.sbom_id.in_(sbom_ids),
                    ThreatDetection.status == "open",
                )
            )
        ).scalars().all()

        vex_statements = (
            await session.execute(
                select(VexStatement).where(
                    VexStatement.organization_id == org_uuid,
                    VexStatement.sbom_id.in_(sbom_ids),
                )
            )
        ).scalars().all()

    vex_not_affected = {v.cve_id for v in vex_statements if v.status in {"not_affected", "fixed"}}
    active_vulns = [v for v in vulns if v.cve_id not in vex_not_affected]
    critical_active = [v for v in active_vulns if (v.severity or "").lower() == "critical"]
    kev_active = [v for v in active_vulns if bool((v.metadata_ or {}).get("in_kev", False))]

    typosquat_or_malware = [t for t in open_threats if t.threat_type in {"typosquatting", "dependency-confusion", "behavioral-risk"}]
    license_threats = [t for t in open_threats if t.threat_type == "license-risk"]
    ai_threats = [t for t in open_threats if t.threat_type == "ai-supply-chain"]
    ai_components = [c for c in all_components if (c.type or "").lower() in {"machine-learning-model", "ml-model", "ai-model", "data"}]

    def _build_framework(code: str, name: str, controls: list[dict[str, Any]]) -> dict[str, Any]:
        passed = sum(1 for c in controls if c["status"] == "pass")
        warned = sum(1 for c in controls if c["status"] == "warn")
        total = max(1, len(controls))
        score = round(((passed + 0.5 * warned) / total) * 100, 1)
        return {
            "framework": code,
            "name": name,
            "score": score,
            "grade": _grade(score),
            "passed_controls": passed,
            "total_controls": len(controls),
            "controls": controls,
        }

    # 1. CISA 2026 Minimum Elements for SBOM
    cisa_controls = [
        {
            "id": "CISA-SBOM-01",
            "title": "Machine-readable SBOM inventory exists",
            "status": "pass" if len(sboms) > 0 and len(all_components) > 0 else "fail",
            "detail": f"{len(sboms)} SBOM(s) tracking {len(all_components)} component(s).",
        },
        {
            "id": "CISA-SBOM-02",
            "title": "CISA 17-field baseline completeness >= 80%",
            "status": "pass" if avg_completeness >= 80 else "warn" if avg_completeness >= 55 else "fail",
            "detail": f"Average SBOM completeness is {avg_completeness}%.",
        },
        {
            "id": "CISA-SBOM-03",
            "title": "Zero unmitigated CISA KEV vulnerabilities",
            "status": "pass" if len(kev_active) == 0 else "fail",
            "detail": f"{len(kev_active)} active CISA KEV vulnerability(ies) without VEX/fix.",
        },
    ]

    # 2. EU Cyber Resilience Act (CRA)
    cra_controls = [
        {
            "id": "CRA-ART13-SBOM",
            "title": "Machine-readable SBOM generated for digital product",
            "status": "pass" if len(sboms) > 0 else "fail",
            "detail": f"{len(sboms)} SBOM(s) stored in CycloneDX/SPDX-compatible format.",
        },
        {
            "id": "CRA-ART14-KEV",
            "title": "No actively exploited vulnerabilities shipped (24h ENISA reporting readiness)",
            "status": "pass" if len(kev_active) == 0 else "fail",
            "detail": f"{len(kev_active)} active KEV finding(s) detected.",
        },
        {
            "id": "CRA-VEX-TRIAGE",
            "title": "Vulnerability Exploitability eXchange (VEX) documentation maintained",
            "status": "pass" if len(vex_statements) > 0 or len(vulns) == 0 else "warn",
            "detail": f"{len(vex_statements)} VEX statement(s) recorded for {len(vulns)} CVE(s).",
        },
        {
            "id": "CRA-LICENSE-IP",
            "title": "Open-source license compliance verified",
            "status": "pass" if len(license_threats) == 0 else "warn",
            "detail": f"{len(license_threats)} strong copyleft license alert(s).",
        },
    ]

    # 3. US FDA Section 524B (Medical / Cyber Devices)
    fda_controls = [
        {
            "id": "FDA-524B-SBOM",
            "title": "Premarket/Postmarket SBOM with component versions & identifiers",
            "status": "pass" if avg_completeness >= 75 and len(all_components) > 0 else "warn" if len(all_components) > 0 else "fail",
            "detail": f"SBOM completeness: {avg_completeness}% across {len(all_components)} component(s).",
        },
        {
            "id": "FDA-524B-CRIT",
            "title": "Zero unresolved Critical CVEs or KEV exposures",
            "status": "pass" if len(critical_active) == 0 and len(kev_active) == 0 else "fail",
            "detail": f"{len(critical_active)} critical CVE(s), {len(kev_active)} KEV CVE(s) unresolved.",
        },
        {
            "id": "FDA-524B-MON",
            "title": "Continuous supply-chain threat monitoring active",
            "status": "pass" if len(typosquat_or_malware) == 0 else "fail",
            "detail": f"{len(typosquat_or_malware)} open typosquatting/malware/confusion threat(s).",
        },
    ]

    # 4. EU AI Act (Annex IV Technical Documentation & AI-BOM)
    ai_controls = [
        {
            "id": "AI-ACT-AIBOM",
            "title": "AI/ML model & dataset provenance cataloged (AI-BOM)",
            "status": "pass" if len(ai_components) > 0 else "warn",
            "detail": f"{len(ai_components)} AI/ML model or dataset component(s) inventoried.",
        },
        {
            "id": "AI-ACT-SAFEWEIGHTS",
            "title": "Safe model serialization (no unsafe pickle weights) & model cards",
            "status": "pass" if len(ai_threats) == 0 else "fail",
            "detail": f"{len(ai_threats)} open AI supply-chain threat(s) detected.",
        },
    ]

    # 5. NIST SP 800-218 (SSDF)
    nist_controls = [
        {
            "id": "SSDF-PW4",
            "title": "Verify third-party software components & dependencies",
            "status": "pass" if len(sboms) > 0 and len(typosquat_or_malware) == 0 else "warn" if len(sboms) > 0 else "fail",
            "detail": f"{len(all_components)} components tracked; {len(typosquat_or_malware)} supply-chain threat(s).",
        },
        {
            "id": "SSDF-RV1",
            "title": "Identify, prioritize, and remediate known vulnerabilities",
            "status": "pass" if len(critical_active) == 0 else "fail",
            "detail": f"{len(active_vulns)} active vulnerabilities ({len(critical_active)} critical).",
        },
    ]

    frameworks = [
        _build_framework("EU_CRA", "EU Cyber Resilience Act (CRA)", cra_controls),
        _build_framework("CISA_2026", "CISA 2026 Minimum Elements (SBOM)", cisa_controls),
        _build_framework("FDA_524B", "US FDA Section 524B (Cyber Devices)", fda_controls),
        _build_framework("EU_AI_ACT", "EU AI Act (Annex IV / AI-BOM)", ai_controls),
        _build_framework("NIST_SSDF", "NIST SP 800-218 (SSDF)", nist_controls),
    ]

    overall = round(sum(f["score"] for f in frameworks) / len(frameworks), 1)
    return {
        "overall_compliance_score": overall,
        "overall_grade": _grade(overall),
        "evaluated_at": utcnow_iso(),
        "scope": {
            "sbom_count": len(sboms),
            "component_count": len(all_components),
            "active_vulnerabilities": len(active_vulns),
            "kev_vulnerabilities": len(kev_active),
            "vex_statements": len(vex_statements),
            "open_threats": len(open_threats),
            "avg_sbom_completeness": avg_completeness,
        },
        "frameworks": frameworks,
    }
