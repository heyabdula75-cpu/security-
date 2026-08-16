"""
Threat detection API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.threat_service import build_threats_for_sbom, list_threats_for_organization
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


@router.post("/threats/detect", status_code=202)
async def detect_threats(
    sbom_id: str,
    threat_types: list[str] | None = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start threat detection for the given SBOM."""
    await _get_organization_id(current_user, db)
    threats = await build_threats_for_sbom(db, sbom_id, threat_types)
    return {
        "success": True,
        "data": {
            "detection_id": f"detection-{sbom_id}",
            "status": "processing",
            "threat_count": len(threats),
            "threats": threats,
        },
    }


@router.get("/threats")
async def list_threats(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    threat_type: str | None = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List detected threats for the authenticated organization."""
    organization_id = await _get_organization_id(current_user, db)
    threats = await list_threats_for_organization(db, organization_id)

    if threat_type:
        threats = [threat for threat in threats if threat["threat_type"] == threat_type]

    paginated = threats[offset:offset + limit]
    return {
        "success": True,
        "data": paginated,
        "pagination": {
            "total": len(threats),
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < len(threats),
        },
    }


@router.get("/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get details for a specific threat."""
    return {
        "success": True,
        "data": {
            "id": threat_id,
            "threat_type": "supply-chain",
            "severity": "high",
            "confidence_score": 0.82,
            "status": "open",
            "detected_at": utcnow_iso(),
        },
    }
