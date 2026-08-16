"""
Vulnerability management API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.vulnerability_service import (
    get_scoped_vulnerability,
    get_user_organization_id,
    list_scoped_vulnerabilities,
    scan_sbom_vulnerabilities,
    serialize_vulnerability,
)

router = APIRouter()


async def _current_organization_id(current_user: dict, db: AsyncSession):
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    try:
        organization_id = await get_user_organization_id(db, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload") from exc

    if not organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User organization not found")
    return organization_id


@router.post("/vulnerabilities/scan", status_code=202)
async def scan_vulnerabilities(
    sbom_id: str,
    deep_scan: bool = False,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start a vulnerability scan for the given SBOM."""
    organization_id = await _current_organization_id(current_user, db)
    try:
        scan = await scan_sbom_vulnerabilities(db, sbom_id, organization_id, deep_scan)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")

    return {
        "success": True,
        "data": scan,
    }

@router.get("/vulnerabilities")
async def list_vulnerabilities(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerabilities for the authenticated organization."""
    organization_id = await _current_organization_id(current_user, db)
    vulnerabilities, total = await list_scoped_vulnerabilities(db, organization_id, limit, offset, severity)

    return {
        "success": True,
        "data": [serialize_vulnerability(vulnerability) for vulnerability in vulnerabilities],
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total,
        }
    }

@router.get("/vulnerabilities/{vulnerability_id}")
async def get_vulnerability(
    vulnerability_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific vulnerability."""
    organization_id = await _current_organization_id(current_user, db)
    try:
        result = await get_scoped_vulnerability(db, vulnerability_id, organization_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    vulnerability, components = result
    return {"success": True, "data": serialize_vulnerability(vulnerability, components)}
