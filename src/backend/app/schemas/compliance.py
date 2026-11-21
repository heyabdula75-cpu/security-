"""
Compliance request and response schemas.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID


# ==================== Policy Schemas ====================

class CompliancePolicyRequest(BaseModel):
    """Request schema for creating/updating compliance policies."""
    framework: str
    control_id: str
    title: str
    description: Optional[str] = None
    requirements: Optional[str] = None
    metadata_: Optional[dict] = Field(None, alias="metadata")


class CompliancePolicyResponse(BaseModel):
    """Response schema for compliance policies."""
    id: UUID
    framework: str
    control_id: str
    title: str
    description: Optional[str]
    requirements: Optional[str]
    status: str
    metadata_: Optional[dict] = Field(None, alias="metadata")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ==================== Report Schemas ====================

class ComplianceReportRequest(BaseModel):
    """Request schema for generating compliance reports."""
    policy_id: UUID
    project_id: Optional[UUID] = None
    title: str


class ComplianceReportResponse(BaseModel):
    """Response schema for compliance reports."""
    id: UUID
    policy_id: UUID
    project_id: Optional[UUID]
    title: str
    status: str
    compliance_score: Optional[str]
    findings_count: Optional[str]
    report_data: Optional[dict]
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class ComplianceReportStatusUpdate(BaseModel):
    """Schema for updating report status."""
    status: str
    compliance_score: Optional[str] = None
    findings_count: Optional[str] = None
    report_data: Optional[dict] = None


# ==================== Audit Log Schemas ====================

class AuditLogResponse(BaseModel):
    """Response schema for audit logs."""
    id: UUID
    user_id: Optional[UUID]
    action: str
    resource_type: str
    resource_id: Optional[UUID]
    resource_name: Optional[str]
    status: str
    details: Optional[dict]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogSummaryResponse(BaseModel):
    """Summary statistics for audit logs."""
    total_logs: int
    by_action: dict = Field(default_factory=dict)
    by_status: dict = Field(default_factory=dict)
    period_days: int


# ==================== List Response Wrappers ====================

class PoliciesListResponse(BaseModel):
    """List response for policies."""
    policies: list[CompliancePolicyResponse]
    total: int
    limit: int
    offset: int


class ReportsListResponse(BaseModel):
    """List response for reports."""
    reports: list[ComplianceReportResponse]
    total: int
    limit: int
    offset: int


class AuditLogsListResponse(BaseModel):
    """List response for audit logs."""
    logs: list[AuditLogResponse]
    total: int
    limit: int
    offset: int
