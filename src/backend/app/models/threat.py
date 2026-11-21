"""
Threat detection model definitions.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class ThreatDetection(Base):
    __tablename__ = "threat_detections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False, index=True)
    component_id = Column(UUID(as_uuid=True), ForeignKey("components.id"), nullable=True, index=True)
    component_name = Column(String(512), nullable=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="medium")
    confidence_score = Column(Float, nullable=False, default=0.75)
    status = Column(String(32), nullable=False, default="open", index=True)
    summary = Column(String(1024), nullable=False)
    evidence = Column(JSON, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    sbom = relationship("Sbom")
    component = relationship("Component")
