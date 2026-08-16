"""
SBOM model definitions.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class Sbom(Base):
    __tablename__ = "sboms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    format = Column(String(64), nullable=False)
    version = Column(String(64), nullable=True)
    content = Column(JSON, nullable=True)
    component_count = Column(Integer, default=0)
    vulnerability_count = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    project = relationship("Project", back_populates="sboms")
    components = relationship("Component", back_populates="sbom")
