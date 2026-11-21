"""Add enterprise tables: threat_detections, vex_statements, api_keys, webhook_endpoints, sbom_signatures.

Revision ID: 20261121_enterprise
Revises:
Create Date: 2026-11-21
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261121_enterprise"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sbom_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sboms.id"), nullable=False),
        sa.Column("component_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("components.id"), nullable=True),
        sa.Column("component_name", sa.String(512), nullable=True),
        sa.Column("threat_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence_score", sa.Float, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("summary", sa.String(1024), nullable=False),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("detected_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )
    op.create_table(
        "vex_statements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("sbom_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sboms.id"), nullable=False),
        sa.Column("cve_id", sa.String(64), nullable=False),
        sa.Column("component_name", sa.String(512), nullable=True),
        sa.Column("component_purl", sa.String(1024), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("justification", sa.String(128), nullable=True),
        sa.Column("impact_statement", sa.Text, nullable=True),
        sa.Column("action_statement", sa.Text, nullable=True),
        sa.Column("author", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("key_prefix", sa.String(32), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("scopes", sa.JSON, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("secret", sa.String(256), nullable=False),
        sa.Column("events", sa.JSON, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False),
        sa.Column("last_triggered_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_table(
        "sbom_signatures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sbom_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sboms.id"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("payload_sha256", sa.String(128), nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("signer", sa.String(256), nullable=False),
        sa.Column("slsa_level", sa.String(32), nullable=False),
        sa.Column("provenance", sa.JSON, nullable=True),
        sa.Column("signed_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sbom_signatures")
    op.drop_table("webhook_endpoints")
    op.drop_table("api_keys")
    op.drop_table("vex_statements")
    op.drop_table("threat_detections")
