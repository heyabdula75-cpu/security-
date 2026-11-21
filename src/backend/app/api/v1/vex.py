"""
VEX (OpenVEX / CycloneDX VEX) and AST Reachability API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models import Component, ComponentVulnerability, Vulnerability
from app.services.auth_service import get_user_by_id
from app.services.reachability_service import evaluate_reachability
from app.services.sbom_service import get_sbom as get_sbom_service
from app.services.vex_service import (
    create_vex_statement,
    export_cyclonedx_vex,
    export_openvex,
    list_vex_statements,
    serialize_vex,
)

router = APIRouter()


class VexCreateRequest(BaseModel):
    sbom_id: str
    cve_id: str
    status: str = Field(..., description="not_affected, affected, fixed, under_investigation")
    component_name: str | None = None
    component_purl: str | None = None
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None


class ReachabilityRequest(BaseModel):
    files: dict[str, str] = Field(..., description="Map of relative file paths to Python/JS/TS source code")
    auto_generate_vex: bool = Field(
        default=False,
        description="Automatically create 'not_affected' VEX statements for unreachable CVEs",
    )


async def _get_org_and_user(current_user: dict, db: AsyncSession) -> tuple[str, str]:
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = await get_user_by_id(db, user_id)
    if not user or not user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User or organization not found")
    return str(user.organization_id), (user.email or "SecureChain User")


@router.post("/vex", status_code=201)
async def create_vex(
    payload: VexCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a VEX attestation for a CVE in an SBOM."""
    org_id, author = await _get_org_and_user(current_user, db)
    sbom = await get_sbom_service(db, payload.sbom_id, org_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    try:
        stmt = await create_vex_statement(
            db,
            organization_id=org_id,
            sbom_id=payload.sbom_id,
            cve_id=payload.cve_id,
            status=payload.status,
            component_name=payload.component_name,
            component_purl=payload.component_purl,
            justification=payload.justification,
            impact_statement=payload.impact_statement,
            action_statement=payload.action_statement,
            author=author,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {"success": True, "data": serialize_vex(stmt)}


@router.get("/vex")
async def list_vex(
    sbom_id: str | None = None,
    cve_id: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List VEX attestations for the authenticated organization."""
    org_id, _ = await _get_org_and_user(current_user, db)
    statements = await list_vex_statements(db, org_id, sbom_id=sbom_id, cve_id=cve_id, status=status_filter)
    return {"success": True, "data": [serialize_vex(s) for s in statements], "total": len(statements)}


@router.get("/sboms/{sbom_id}/vex/export")
async def export_vex(
    sbom_id: str,
    format: str = Query(default="openvex", pattern="^(openvex|cyclonedx)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export VEX statements for an SBOM in OpenVEX or CycloneDX VEX JSON format."""
    org_id, author = await _get_org_and_user(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, org_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    statements = await list_vex_statements(db, org_id, sbom_id=sbom_id)
    doc = export_cyclonedx_vex(sbom_id, statements) if format == "cyclonedx" else export_openvex(sbom_id, statements, author)
    return {"success": True, "format": format, "data": doc}


@router.post("/sboms/{sbom_id}/reachability")
async def analyze_sbom_reachability(
    sbom_id: str,
    payload: ReachabilityRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run Python/JS/TS AST reachability analysis against vulnerabilities found in an SBOM."""
    org_id, author = await _get_org_and_user(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, org_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    rows = (
        await db.execute(
            select(Component, Vulnerability)
            .join(ComponentVulnerability, ComponentVulnerability.component_id == Component.id)
            .join(Vulnerability, ComponentVulnerability.vulnerability_id == Vulnerability.id)
            .where(Component.sbom_id == sbom.id)
        )
    ).all()

    findings = [
        {"component_name": comp.name, "component_purl": comp.purl, "cve_id": vuln.cve_id}
        for comp, vuln in rows
    ]
    report = evaluate_reachability(payload.files, findings)

    auto_created_vex = []
    if payload.auto_generate_vex:
        for item in report["results"]:
            if item["reachability"] == "unreachable":
                stmt = await create_vex_statement(
                    db,
                    organization_id=org_id,
                    sbom_id=sbom_id,
                    cve_id=item["cve_id"],
                    status="not_affected",
                    component_name=item["component_name"],
                    component_purl=item["component_purl"],
                    justification="vulnerable_code_not_in_execute_path",
                    impact_statement=item["reason"],
                    author=f"SecureChain AST Reachability ({author})",
                )
                auto_created_vex.append(serialize_vex(stmt))

    report["auto_created_vex"] = auto_created_vex
    return {"success": True, "data": report}
