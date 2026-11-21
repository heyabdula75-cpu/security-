"""
Compliance model definitions.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, String, Text, Enum, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.models.base import Base


class ComplianceFramework(str, enum.Enum):
    """Compliance framework types."""
    NIST = "NIST_CSF"
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    CIS = "CIS_CONTROLS"
    EU_CRA = "EU_CRA"
    CISA_2026 = "CISA_2026"
    FDA_524B = "FDA_524B"
    EU_AI_ACT = "EU_AI_ACT"


class PolicyStatus(str, enum.Enum):
    """Policy status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"


class ReportStatus(str, enum.Enum):
    """Report generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditAction(str, enum.Enum):
    """Audit log action types."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    READ = "read"
    VERIFY = "verify"
    SCAN = "scan"
    EXPORT = "export"


class CompliancePolicy(Base):
    """Compliance policies define requirements and controls."""
    __tablename__ = "compliance_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    control_id = Column(String(128), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    requirements = Column(Text, nullable=True)
    status = Column(Enum(PolicyStatus), default=PolicyStatus.ACTIVE, nullable=False)
    metadata_ = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="compliance_policies")
    reports = relationship("ComplianceReport", back_populates="policy")


class ComplianceReport(Base):
    """Compliance reports show compliance status against policies."""
    __tablename__ = "compliance_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("compliance_policies.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True)
    title = Column(String(512), nullable=False)
    status = Column(Enum(ReportStatus), default=ReportStatus.PENDING, nullable=False)
    compliance_score = Column(String(10), nullable=True)  # e.g., "85%"
    findings_count = Column(String(50), nullable=True)  # JSON serialized counts
    report_data = Column(JSON, nullable=True)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    organization = relationship("Organization")
    policy = relationship("CompliancePolicy", back_populates="reports")
    project = relationship("Project")
    user = relationship("User")


class AuditLog(Base):
    """Audit logs track all system actions for compliance."""
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(Enum(AuditAction), nullable=False, index=True)
    resource_type = Column(String(128), nullable=False, index=True)  # e.g., "sbom", "vulnerability"
    resource_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    resource_name = Column(String(512), nullable=True)
    status = Column(String(50), nullable=False)  # "success", "failure"
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    organization = relationship("Organization")
    user = relationship("User")
