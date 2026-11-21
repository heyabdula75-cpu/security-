"""
VEX (Vulnerability Exploitability eXchange) service:
- Create & list persisted VEX attestations
- Export OpenVEX (v0.2.0) and CycloneDX 1.5 VEX JSON documents
"""
from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vex import VEX_JUSTIFICATIONS, VEX_STATUSES, VexStatement
from app.utils.time_utils import utcnow_iso


def _as_uuid(value: str | UUID) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def serialize_vex(stmt: VexStatement) -> dict[str, Any]:
    return {
        "id": str(stmt.id),
        "organization_id": str(stmt.organization_id),
        "sbom_id": str(stmt.sbom_id),
        "cve_id": stmt.cve_id,
        "component_name": stmt.component_name,
        "component_purl": stmt.component_purl,
        "status": stmt.status,
        "justification": stmt.justification,
        "impact_statement": stmt.impact_statement,
        "action_statement": stmt.action_statement,
        "author": stmt.author,
        "created_at": (stmt.created_at.isoformat() + "Z") if stmt.created_at else utcnow_iso(),
    }


async def create_vex_statement(
    session: AsyncSession,
    organization_id: str | UUID,
    sbom_id: str | UUID,
    cve_id: str,
    status: str,
    component_name: str | None = None,
    component_purl: str | None = None,
    justification: str | None = None,
    impact_statement: str | None = None,
    action_statement: str | None = None,
    author: str | None = "SecureChain Security Team",
) -> VexStatement:
    norm_status = status.lower().strip()
    if norm_status not in VEX_STATUSES:
        raise ValueError(f"Invalid VEX status '{status}'. Allowed: {', '.join(sorted(VEX_STATUSES))}")
    if justification and justification not in VEX_JUSTIFICATIONS:
        raise ValueError(f"Invalid VEX justification '{justification}'. Allowed: {', '.join(sorted(VEX_JUSTIFICATIONS))}")

    record = VexStatement(
        organization_id=_as_uuid(organization_id),
        sbom_id=_as_uuid(sbom_id),
        cve_id=cve_id.upper().strip(),
        component_name=component_name,
        component_purl=component_purl,
        status=norm_status,
        justification=justification,
        impact_statement=impact_statement,
        action_statement=action_statement,
        author=author,
    )
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


async def list_vex_statements(
    session: AsyncSession,
    organization_id: str | UUID,
    sbom_id: str | UUID | None = None,
    cve_id: str | None = None,
    status: str | None = None,
) -> list[VexStatement]:
    conditions = [VexStatement.organization_id == _as_uuid(organization_id)]
    if sbom_id:
        conditions.append(VexStatement.sbom_id == _as_uuid(sbom_id))
    if cve_id:
        conditions.append(VexStatement.cve_id == cve_id.upper().strip())
    if status:
        conditions.append(VexStatement.status == status.lower().strip())

    query = select(VexStatement).where(*conditions).order_by(VexStatement.created_at.desc())
    result = await session.execute(query)
    return result.scalars().all()


def export_openvex(sbom_id: str, statements: list[VexStatement], author: str = "SecureChain Platform") -> dict[str, Any]:
    """Export VEX statements in OpenVEX v0.2.0 JSON-LD format."""
    openvex_statements = []
    for stmt in statements:
        entry: dict[str, Any] = {
            "vulnerability": {"name": stmt.cve_id},
            "products": [{"@id": stmt.component_purl or f"pkg:generic/{stmt.component_name or 'component'}"}],
            "status": stmt.status,
            "timestamp": (stmt.created_at.isoformat() + "Z") if stmt.created_at else utcnow_iso(),
        }
        if stmt.justification:
            entry["justification"] = stmt.justification
        if stmt.impact_statement:
            entry["impact_statement"] = stmt.impact_statement
        if stmt.action_statement:
            entry["action_statement"] = stmt.action_statement
        openvex_statements.append(entry)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://securechain.local/vex/{sbom_id}-{uuid4().hex[:8]}",
        "author": author,
        "timestamp": utcnow_iso(),
        "version": 1,
        "statements": openvex_statements,
    }


def export_cyclonedx_vex(sbom_id: str, statements: list[VexStatement]) -> dict[str, Any]:
    """Export VEX statements in CycloneDX 1.5 VEX format."""
    state_map = {
        "not_affected": "not_affected",
        "affected": "exploitable",
        "fixed": "resolved",
        "under_investigation": "in_triage",
    }
    cdx_vulns = []
    for stmt in statements:
        analysis: dict[str, Any] = {"state": state_map.get(stmt.status, "in_triage")}
        if stmt.justification:
            analysis["justification"] = stmt.justification
        if stmt.impact_statement or stmt.action_statement:
            analysis["detail"] = stmt.impact_statement or stmt.action_statement

        cdx_vulns.append(
            {
                "id": stmt.cve_id,
                "analysis": analysis,
                "affects": [{"ref": stmt.component_purl or stmt.component_name or sbom_id}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utcnow_iso(),
            "tools": [{"vendor": "SecureChain", "name": "SecureChain VEX Engine", "version": "1.1.0"}],
        },
        "vulnerabilities": cdx_vulns,
    }
