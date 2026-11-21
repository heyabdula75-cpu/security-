"""
VEX (Vulnerability Exploitability eXchange) statement model definitions.
Supports OpenVEX and CycloneDX VEX standards.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base

VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
VEX_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


class VexStatement(Base):
    __tablename__ = "vex_statements"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False, index=True)
    cve_id = Column(String(64), nullable=False, index=True)
    component_name = Column(String(512), nullable=True)
    component_purl = Column(String(1024), nullable=True)
    status = Column(String(32), nullable=False)  # not_affected, affected, fixed, under_investigation
    justification = Column(String(128), nullable=True)
    impact_statement = Column(Text, nullable=True)
    action_statement = Column(Text, nullable=True)
    author = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    sbom = relationship("Sbom")
