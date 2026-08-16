"""
Project model definitions.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(256), nullable=False, index=True)
    slug = Column(String(256), nullable=False, unique=True, index=True)
    description = Column(String(1024), nullable=True)
    repository_url = Column(String(1024), nullable=True)
    repository_type = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="projects")
    sboms = relationship("Sbom", back_populates="project")
