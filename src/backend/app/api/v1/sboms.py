"""
SBOM management API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.sbom_service import create_sbom, get_component as get_component_service
from app.services.sbom_service import get_project_by_id, get_sbom as get_sbom_service, list_components as list_components_service
from app.services.sbom_service import list_sboms as list_sboms_service
from app.utils.time_utils import utcnow_iso

router = APIRouter()


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
            "vulnerability_count": 0,
            "risk_score": 0.0,
        },
    }
