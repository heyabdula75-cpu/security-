"""
Risk scoring API routes.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.risk_service import calculate_sbom_risk, get_component_recommendations as get_component_recommendations_service

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


@router.get("/sboms/{sbom_id}/risk-score")
async def get_sbom_risk_score(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregate risk score for an SBOM."""
    await _get_organization_id(current_user, db)
    risk = await calculate_sbom_risk(db, sbom_id)
    return {"success": True, "data": risk}


@router.get("/components/{component_id}/recommendations")
async def get_component_recommendations(
    component_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get remediation recommendations for a component."""
    await _get_organization_id(current_user, db)
    recommendations = await get_component_recommendations_service(db, component_id)
    return {"success": True, "data": recommendations}
