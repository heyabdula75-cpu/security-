"""
Compliance Management API routes
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models import ComplianceFramework, ReportStatus
from app.schemas.compliance import (
    CompliancePolicyRequest,
    CompliancePolicyResponse,
    ComplianceReportRequest,
    ComplianceReportResponse,
    ComplianceReportStatusUpdate,
    AuditLogResponse,
    AuditLogSummaryResponse,
    PoliciesListResponse,
    ReportsListResponse,
    AuditLogsListResponse,
)
from app.services import compliance_service
from app.services.compliance_evaluator import evaluate_organization_compliance

router = APIRouter()


@router.get("/compliance/evaluate")
async def evaluate_compliance(
    sbom_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Automatically evaluate live SBOMs, CVEs, KEV, VEX, and threats against EU CRA, CISA 2026, FDA 524B, EU AI Act, and NIST SSDF."""
    org_id = current_user.get("organization_id")
    if not org_id:
        from app.services.auth_service import get_user_by_id

        user = await get_user_by_id(db, current_user.get("sub", ""))
        if not user or not user.organization_id:
            raise HTTPException(status_code=404, detail="Organization not found")
        org_id = str(user.organization_id)

    evaluation = await evaluate_organization_compliance(db, org_id, sbom_id=sbom_id)
    return {"success": True, "data": evaluation}


# ==================== Compliance Policies ====================

@router.get("/compliance/policies", response_model=PoliciesListResponse)
async def list_policies(
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List compliance policies for organization."""
    org_id = UUID(current_user.get("organization_id"))
    
    framework_enum = None
    if framework:
        try:
            framework_enum = ComplianceFramework[framework.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail="Invalid framework")
    
    policies = await compliance_service.list_policies(
        db,
        organization_id=org_id,
        framework=framework_enum,
        status=status,
        limit=limit,
        offset=offset,
    )
    
    return PoliciesListResponse(
        policies=[CompliancePolicyResponse.from_orm(p) for p in policies],
        total=len(policies),
        limit=limit,
        offset=offset,
    )


@router.post("/compliance/policies", status_code=201, response_model=CompliancePolicyResponse)
async def create_policy(
    req: CompliancePolicyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new compliance policy."""
    org_id = UUID(current_user.get("organization_id"))
    
    try:
        framework_enum = ComplianceFramework[req.framework.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid framework")
    
    policy = await compliance_service.create_policy(
        db,
        organization_id=org_id,
        framework=framework_enum,
        control_id=req.control_id,
        title=req.title,
        description=req.description,
        requirements=req.requirements,
        metadata=req.metadata_,
    )
    
    return CompliancePolicyResponse.from_orm(policy)


@router.get("/compliance/policies/{policy_id}", response_model=CompliancePolicyResponse)
async def get_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific compliance policy."""
    policy = await compliance_service.get_policy(db, policy_id)
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    if str(policy.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    return CompliancePolicyResponse.from_orm(policy)


@router.put("/compliance/policies/{policy_id}", response_model=CompliancePolicyResponse)
async def update_policy(
    policy_id: UUID,
    req: CompliancePolicyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a compliance policy."""
    policy = await compliance_service.get_policy(db, policy_id)
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    if str(policy.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    updated = await compliance_service.update_policy(
        db,
        policy_id,
        title=req.title,
        description=req.description,
        requirements=req.requirements,
        metadata_=req.metadata_,
    )
    
    return CompliancePolicyResponse.from_orm(updated)


@router.delete("/compliance/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a compliance policy."""
    policy = await compliance_service.get_policy(db, policy_id)
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    if str(policy.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    await compliance_service.delete_policy(db, policy_id)


# ==================== Compliance Reports ====================

@router.get("/compliance/reports", response_model=ReportsListResponse)
async def list_reports(
    policy_id: Optional[UUID] = Query(None),
    project_id: Optional[UUID] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List compliance reports for organization."""
    org_id = UUID(current_user.get("organization_id"))
    
    status_enum = None
    if status:
        try:
            status_enum = ReportStatus[status.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail="Invalid status")
    
    reports = await compliance_service.list_reports(
        db,
        organization_id=org_id,
        policy_id=policy_id,
        project_id=project_id,
        status=status_enum,
        limit=limit,
        offset=offset,
    )
    
    return ReportsListResponse(
        reports=[ComplianceReportResponse.from_orm(r) for r in reports],
        total=len(reports),
        limit=limit,
        offset=offset,
    )


@router.post("/compliance/reports", status_code=201, response_model=ComplianceReportResponse)
async def generate_report(
    req: ComplianceReportRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new compliance report."""
    org_id = UUID(current_user.get("organization_id"))
    user_id = UUID(current_user.get("user_id"))
    
    report = await compliance_service.create_report(
        db,
        organization_id=org_id,
        policy_id=req.policy_id,
        project_id=req.project_id,
        title=req.title,
        generated_by=user_id,
    )
    
    return ComplianceReportResponse.from_orm(report)


@router.get("/compliance/reports/{report_id}", response_model=ComplianceReportResponse)
async def get_report(
    report_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific compliance report."""
    report = await compliance_service.get_report(db, report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if str(report.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    return ComplianceReportResponse.from_orm(report)


@router.patch("/compliance/reports/{report_id}", response_model=ComplianceReportResponse)
async def update_report(
    report_id: UUID,
    req: ComplianceReportStatusUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a compliance report status."""
    report = await compliance_service.get_report(db, report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if str(report.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    try:
        status_enum = ReportStatus[req.status.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    updated = await compliance_service.update_report_status(
        db,
        report_id,
        status=status_enum,
        compliance_score=req.compliance_score,
        findings_count=req.findings_count,
        report_data=req.report_data,
    )
    
    return ComplianceReportResponse.from_orm(updated)


@router.delete("/compliance/reports/{report_id}", status_code=204)
async def delete_report(
    report_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a compliance report."""
    report = await compliance_service.get_report(db, report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if str(report.organization_id) != current_user.get("organization_id"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    await compliance_service.delete_report(db, report_id)


# ==================== Audit Logs ====================

@router.get("/audit-logs", response_model=AuditLogsListResponse)
async def list_audit_logs(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    resource_id: Optional[UUID] = Query(None),
    days: int = Query(90, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List audit logs for organization."""
    org_id = UUID(current_user.get("organization_id"))
    
    logs = await compliance_service.list_audit_logs(
        db,
        organization_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        days=days,
        limit=limit,
        offset=offset,
    )
    
    return AuditLogsListResponse(
        logs=[AuditLogResponse.from_orm(log) for log in logs],
        total=len(logs),
        limit=limit,
        offset=offset,
    )


@router.get("/audit-logs/summary", response_model=AuditLogSummaryResponse)
async def get_audit_summary(
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get summary statistics for audit logs."""
    org_id = UUID(current_user.get("organization_id"))
    
    summary = await compliance_service.get_audit_summary(db, org_id, days=days)
    return AuditLogSummaryResponse(**summary)
