"""
Enterprise Trust & Automation models:
- Scoped API Keys (DB-backed SHA-256 hashed keys for CLI & CI/CD)
- Webhook Endpoints (Slack, Teams, Jira, SIEM alerting)
- Cryptographic SBOM Signatures & SLSA Provenance attestations
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    name = Column(String(256), nullable=False)
    key_prefix = Column(String(32), nullable=False)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    scopes = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(256), nullable=False)
    url = Column(String(1024), nullable=False)
    secret = Column(String(256), nullable=False)
    events = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, default=True, nullable=False)
    last_triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SbomSignature(Base):
    __tablename__ = "sbom_signatures"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    algorithm = Column(String(64), nullable=False, default="HMAC-SHA256-DSSE")
    payload_sha256 = Column(String(128), nullable=False)
    signature = Column(Text, nullable=False)
    signer = Column(String(256), nullable=False)
    slsa_level = Column(String(32), nullable=False, default="SLSA_BUILD_L2")
    provenance = Column(JSON, nullable=True)
    signed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    sbom = relationship("Sbom")
