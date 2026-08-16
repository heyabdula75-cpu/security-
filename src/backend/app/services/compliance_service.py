"""
Compliance service for managing policies, reports, and audit logs.
"""
from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CompliancePolicy, ComplianceReport, AuditLog, ComplianceFramework, PolicyStatus, ReportStatus, AuditAction


# ==================== Policy Operations ====================

async def create_policy(
    session: AsyncSession,
    organization_id: UUID,
    framework: ComplianceFramework,
    control_id: str,
    title: str,
    description: Optional[str] = None,
    requirements: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> CompliancePolicy:
    """Create a new compliance policy."""
    policy = CompliancePolicy(
        organization_id=organization_id,
        framework=framework,
        control_id=control_id,
        title=title,
        description=description,
        requirements=requirements,
        metadata_=metadata,
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


async def get_policy(session: AsyncSession, policy_id: UUID) -> Optional[CompliancePolicy]:
    """Get a policy by ID."""
    stmt = select(CompliancePolicy).where(CompliancePolicy.id == policy_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_policies(
    session: AsyncSession,
    organization_id: UUID,
    framework: Optional[ComplianceFramework] = None,
    status: Optional[PolicyStatus] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CompliancePolicy]:
    """List compliance policies with optional filters."""
    conditions = [CompliancePolicy.organization_id == organization_id]
    
    if framework:
        conditions.append(CompliancePolicy.framework == framework)
    if status:
        conditions.append(CompliancePolicy.status == status)
    
    stmt = (
        select(CompliancePolicy)
        .where(and_(*conditions))
        .order_by(CompliancePolicy.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    return result.scalars().all()


async def update_policy(
    session: AsyncSession,
    policy_id: UUID,
    **kwargs
) -> Optional[CompliancePolicy]:
    """Update a compliance policy."""
    policy = await get_policy(session, policy_id)
    if not policy:
        return None
    
    # Only allow updating specific fields
    allowed_fields = {"title", "description", "requirements", "status", "metadata_"}
    for key, value in kwargs.items():
        if key in allowed_fields:
            setattr(policy, key, value)
    
    policy.updated_at = datetime.utcnow()
    await session.commit()
    await session.refresh(policy)
    return policy


async def delete_policy(session: AsyncSession, policy_id: UUID) -> bool:
    """Delete a compliance policy."""
    policy = await get_policy(session, policy_id)
    if not policy:
        return False
    
    await session.delete(policy)
    await session.commit()
    return True


# ==================== Report Operations ====================

async def create_report(
    session: AsyncSession,
    organization_id: UUID,
    policy_id: UUID,
    title: str,
    project_id: Optional[UUID] = None,
    generated_by: Optional[UUID] = None,
) -> ComplianceReport:
    """Create a new compliance report."""
    report = ComplianceReport(
        organization_id=organization_id,
        policy_id=policy_id,
        project_id=project_id,
        title=title,
        status=ReportStatus.PENDING,
        generated_by=generated_by,
    )
    session.add(report)
    await session.commit()
    await session.refresh(report)
    return report


async def get_report(session: AsyncSession, report_id: UUID) -> Optional[ComplianceReport]:
    """Get a report by ID."""
    stmt = select(ComplianceReport).where(ComplianceReport.id == report_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_reports(
    session: AsyncSession,
    organization_id: UUID,
    policy_id: Optional[UUID] = None,
    project_id: Optional[UUID] = None,
    status: Optional[ReportStatus] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[ComplianceReport]:
    """List compliance reports with optional filters."""
    conditions = [ComplianceReport.organization_id == organization_id]
    
    if policy_id:
        conditions.append(ComplianceReport.policy_id == policy_id)
    if project_id:
        conditions.append(ComplianceReport.project_id == project_id)
    if status:
        conditions.append(ComplianceReport.status == status)
    
    stmt = (
        select(ComplianceReport)
        .where(and_(*conditions))
        .order_by(ComplianceReport.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    return result.scalars().all()


async def update_report_status(
    session: AsyncSession,
    report_id: UUID,
    status: ReportStatus,
    compliance_score: Optional[str] = None,
    findings_count: Optional[str] = None,
    report_data: Optional[dict] = None,
) -> Optional[ComplianceReport]:
    """Update a report's status and findings."""
    report = await get_report(session, report_id)
    if not report:
        return None
    
    report.status = status
    if compliance_score:
        report.compliance_score = compliance_score
    if findings_count:
        report.findings_count = findings_count
    if report_data:
        report.report_data = report_data
    
    if status == ReportStatus.COMPLETED:
        report.completed_at = datetime.utcnow()
    
    await session.commit()
    await session.refresh(report)
    return report


async def delete_report(session: AsyncSession, report_id: UUID) -> bool:
    """Delete a compliance report."""
    report = await get_report(session, report_id)
    if not report:
        return False
    
    await session.delete(report)
    await session.commit()
    return True


# ==================== Audit Log Operations ====================

async def create_audit_log(
    session: AsyncSession,
    organization_id: UUID,
    action: AuditAction,
    resource_type: str,
    status: str,
    user_id: Optional[UUID] = None,
    resource_id: Optional[UUID] = None,
    resource_name: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """Create an audit log entry."""
    log = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        status=status,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    session.add(log)
    await session.commit()
    await session.refresh(log)
    return log


async def list_audit_logs(
    session: AsyncSession,
    organization_id: UUID,
    user_id: Optional[UUID] = None,
    action: Optional[AuditAction] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[UUID] = None,
    days: int = 90,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    """List audit logs with optional filters. Default: last 90 days."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    conditions = [
        AuditLog.organization_id == organization_id,
        AuditLog.created_at >= cutoff_date,
    ]
    
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if action:
        conditions.append(AuditLog.action == action)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditLog.resource_id == resource_id)
    
    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    return result.scalars().all()


async def get_audit_summary(
    session: AsyncSession,
    organization_id: UUID,
    days: int = 30,
) -> dict:
    """Get summary statistics of audit logs."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    stmt = select(AuditLog).where(
        and_(
            AuditLog.organization_id == organization_id,
            AuditLog.created_at >= cutoff_date,
        )
    )
    result = await session.execute(stmt)
    logs = result.scalars().all()
    
    # Aggregate by action and status
    by_action = {}
    by_status = {}
    for log in logs:
        by_action[log.action.value] = by_action.get(log.action.value, 0) + 1
        by_status[log.status] = by_status.get(log.status, 0) + 1
    
    return {
        "total_logs": len(logs),
        "by_action": by_action,
        "by_status": by_status,
        "period_days": days,
    }
