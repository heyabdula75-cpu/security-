"""
Component model definitions.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class Component(Base):
    __tablename__ = "components"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False)
    name = Column(String(512), nullable=False, index=True)
    version = Column(String(128), nullable=True)
    type = Column(String(128), nullable=True)
    purl = Column(String(1024), nullable=True)
    license = Column(String(256), nullable=True)
    author = Column(String(256), nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    sbom = relationship("Sbom", back_populates="components")
    vulnerabilities = relationship("ComponentVulnerability", back_populates="component")
