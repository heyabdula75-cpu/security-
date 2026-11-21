"""
SBOM management API routes:
- Generate, Upload/Parse (CycloneDX, SPDX, npm, PyPI, Go, Dockerfile)
- List, Retrieve, Export (CycloneDX 1.5 / SPDX 2.3)
- Diff two SBOMs
- CISA 2026 Minimum Elements Completeness Scoring
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.sbom_parser import (
    diff_sboms,
    evaluate_sbom_completeness,
    export_cyclonedx,
    export_spdx,
    parse_sbom_input,
)
from app.services.sbom_service import (
    create_sbom,
    get_component as get_component_service,
    get_project_by_id,
    get_sbom as get_sbom_service,
    list_components as list_components_service,
    list_sboms as list_sboms_service,
)
from app.services.threat_service import build_threats_for_sbom
from app.services.vulnerability_service import scan_sbom_vulnerabilities
from app.utils.time_utils import utcnow_iso

router = APIRouter()


class SbomUploadRequest(BaseModel):
    project_id: str
    source_type: str = Field(
        default="auto",
        description="Format: auto, cyclonedx-json, spdx-json, package-lock.json, package.json, requirements.txt, go.mod, dockerfile",
    )
    content: str | dict[str, Any]
    version: str | None = "1.0"
    auto_scan: bool = True


async def _get_organization_id(current_user: dict, db: AsyncSession) -> str:
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User organization not found")

    return str(user.organization_id)


@router.post("/sboms/upload", status_code=201)
async def upload_and_parse_sbom(
    payload: SbomUploadRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a lockfile, Dockerfile, CycloneDX, or SPDX SBOM, parse components, and optionally scan immediately."""
    organization_id = await _get_organization_id(current_user, db)
    project = await get_project_by_id(db, payload.project_id)
    if not project or str(project.organization_id) != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    detected_format, components_data = parse_sbom_input(payload.source_type, payload.content)
    stored_content = payload.content if isinstance(payload.content, dict) else {"raw_source": detected_format}

    sbom = await create_sbom(
        db,
        project_id=payload.project_id,
        sbom_format=detected_format,
        version=payload.version or "1.0",
        content=stored_content,
        components_data=components_data,
    )

    scan_result = None
    threats = []
    if payload.auto_scan:
        from uuid import UUID

        scan_result = await scan_sbom_vulnerabilities(db, str(sbom.id), UUID(organization_id))
        threats = await build_threats_for_sbom(db, sbom.id)
        await db.refresh(sbom)

    return {
        "success": True,
        "data": {
            "id": str(sbom.id),
            "project_id": str(sbom.project_id),
            "format": sbom.format,
            "version": sbom.version,
            "component_count": sbom.component_count,
            "vulnerability_count": sbom.vulnerability_count,
            "threat_count": len(threats),
            "risk_score": sbom.risk_score,
            "generated_at": sbom.generated_at.isoformat() + "Z",
            "scan": scan_result,
            "threats": threats,
        },
    }


@router.post("/sboms/generate", status_code=202)
async def generate_sbom(
    project_id: str,
    source: str,
    repository_url: str,
    branch: str = "main",
    format: str = "cyclonedx-json",
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start SBOM generation for a repository."""
    organization_id = await _get_organization_id(current_user, db)
    project = await get_project_by_id(db, project_id)
    if not project or str(project.organization_id) != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    sbom = await create_sbom(
        db,
        project_id=project_id,
        sbom_format=format,
        version="1.0",
        content={"source": source, "repository_url": repository_url, "branch": branch},
        components_data=[],
    )

    return {
        "success": True,
        "data": {
            "job_id": str(sbom.id),
            "status": "processing",
            "estimated_completion": utcnow_iso(),
            "sbom_id": str(sbom.id),
        },
    }


@router.get("/sboms/diff")
async def compare_sboms(
    base_sbom_id: str,
    head_sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Diff two SBOMs to identify added, removed, and upgraded components."""
    organization_id = await _get_organization_id(current_user, db)
    base_sbom = await get_sbom_service(db, base_sbom_id, organization_id)
    head_sbom = await get_sbom_service(db, head_sbom_id, organization_id)
    if not base_sbom or not head_sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both SBOMs not found")

    base_components = await list_components_service(db, base_sbom_id, limit=5000, offset=0)
    head_components = await list_components_service(db, head_sbom_id, limit=5000, offset=0)

    return {
        "success": True,
        "data": {
            "base_sbom_id": base_sbom_id,
            "head_sbom_id": head_sbom_id,
            **diff_sboms(base_components, head_components),
        },
    }


@router.get("/sboms")
async def list_sboms(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List SBOMs for the authenticated organization."""
    organization_id = await _get_organization_id(current_user, db)
    sboms = await list_sboms_service(db, organization_id, limit, offset)
    return {
        "success": True,
        "data": [
            {
                "id": str(sbom.id),
                "project_id": str(sbom.project_id),
                "format": sbom.format,
                "version": sbom.version,
                "component_count": sbom.component_count,
                "vulnerability_count": sbom.vulnerability_count,
                "risk_score": sbom.risk_score,
                "generated_at": sbom.generated_at.isoformat() + "Z",
            }
            for sbom in sboms
        ],
        "pagination": {
            "total": len(sboms),
            "limit": limit,
            "offset": offset,
            "has_more": len(sboms) == limit,
        },
    }


@router.get("/sboms/{sbom_id}")
async def get_sbom(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a specific SBOM."""
    organization_id = await _get_organization_id(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, organization_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    return {
        "success": True,
        "data": {
            "id": str(sbom.id),
            "project_id": str(sbom.project_id),
            "format": sbom.format,
            "version": sbom.version,
            "component_count": sbom.component_count,
            "vulnerability_count": sbom.vulnerability_count,
            "risk_score": sbom.risk_score,
            "generated_at": sbom.generated_at.isoformat() + "Z",
        },
    }


@router.get("/sboms/{sbom_id}/export")
async def export_sbom(
    sbom_id: str,
    format: str = Query(default="cyclonedx", pattern="^(cyclonedx|spdx)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export an SBOM in standardized CycloneDX 1.5 or SPDX 2.3 JSON format."""
    organization_id = await _get_organization_id(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, organization_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    project = await get_project_by_id(db, str(sbom.project_id))
    project_name = project.name if project else "SecureChain Project"
    components = await list_components_service(db, sbom_id, limit=5000, offset=0)

    document = export_spdx(sbom, components, project_name) if format == "spdx" else export_cyclonedx(sbom, components, project_name)
    return {"success": True, "format": format, "data": document}


@router.get("/sboms/{sbom_id}/completeness")
async def get_sbom_completeness(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Evaluate SBOM completeness against CISA 2026 Minimum Elements."""
    organization_id = await _get_organization_id(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, organization_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    components = await list_components_service(db, sbom_id, limit=5000, offset=0)
    return {"success": True, "data": evaluate_sbom_completeness(sbom, components)}


@router.get("/components")
async def list_components(
    sbom_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List components for a given SBOM."""
    organization_id = await _get_organization_id(current_user, db)
    sbom = await get_sbom_service(db, sbom_id, organization_id)
    if not sbom:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    components = await list_components_service(db, sbom_id, limit, offset)
    return {
        "success": True,
        "data": [
            {
                "id": str(component.id),
                "name": component.name,
                "version": component.version,
                "type": component.type,
                "purl": component.purl,
                "license": component.license,
                "author": component.author,
                "vulnerability_count": 0,
                "risk_score": 0.0,
            }
            for component in components
        ],
        "pagination": {
            "total": len(components),
            "limit": limit,
            "offset": offset,
            "has_more": len(components) == limit,
        },
    }


@router.get("/components/{component_id}")
async def get_component(
    component_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get component details."""
    component = await get_component_service(db, component_id)
    if not component:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Component not found")

    return {
        "success": True,
        "data": {
            "id": str(component.id),
            "name": component.name,
            "version": component.version,
            "type": component.type,
            "purl": component.purl,
            "license": component.license,
            "author": component.author,
            "vulnerability_count": 0,
            "risk_score": 0.0,
        },
    }
