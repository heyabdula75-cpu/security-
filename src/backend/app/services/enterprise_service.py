"""
Enterprise Trust & Automation Services:
- Scoped API Keys (SHA-256 hashed, prefix-indexed)
- Cryptographic SBOM Signing & Tamper Verification (HMAC-SHA256 DSSE + SLSA provenance)
- Enterprise Webhooks (HMAC-signed event delivery for Slack/Teams/Jira/SIEM)
- Auto-Fix Patch & PR Diff Generator
- One-Click Regulatory Audit Evidence Bundle
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    ApiKey,
    Component,
    ComponentVulnerability,
    Project,
    Sbom,
    SbomSignature,
    Vulnerability,
    WebhookEndpoint,
)
from app.services.compliance_evaluator import evaluate_organization_compliance
from app.services.risk_service import calculate_sbom_risk
from app.services.sbom_parser import evaluate_sbom_completeness, export_cyclonedx
from app.services.sbom_service import get_project_by_id, get_sbom, list_components
from app.services.vex_service import export_openvex, list_vex_statements
from app.utils.time_utils import utcnow, utcnow_iso


def _as_uuid(value: str | UUID) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


# ==================== Scoped API Keys ====================

async def create_api_key(
    session: AsyncSession,
    organization_id: str | UUID,
    user_id: str | UUID | None,
    name: str,
    scopes: list[str] | None = None,
) -> tuple[ApiKey, str]:
    """Create a hashed API key. Returns (record, raw_plaintext_key_once)."""
    raw_secret = f"sc_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
    record = ApiKey(
        organization_id=_as_uuid(organization_id),
        user_id=_as_uuid(user_id) if user_id else None,
        name=name.strip() or "CI/CD Service Key",
        key_prefix=raw_secret[:14],
        key_hash=key_hash,
        scopes=scopes or ["sbom:read", "scan:write", "compliance:read"],
        is_active=True,
    )
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record, raw_secret


async def list_api_keys(session: AsyncSession, organization_id: str | UUID) -> list[ApiKey]:
    stmt = (
        select(ApiKey)
        .where(ApiKey.organization_id == _as_uuid(organization_id))
        .order_by(ApiKey.created_at.desc())
    )
    return (await session.execute(stmt)).scalars().all()


async def revoke_api_key(session: AsyncSession, key_id: str | UUID, organization_id: str | UUID) -> bool:
    stmt = select(ApiKey).where(
        ApiKey.id == _as_uuid(key_id),
        ApiKey.organization_id == _as_uuid(organization_id),
    )
    record = (await session.execute(stmt)).scalars().first()
    if not record:
        return False
    record.is_active = False
    await session.commit()
    return True


async def verify_api_key(session: AsyncSession, raw_key: str) -> ApiKey | None:
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
    record = (await session.execute(stmt)).scalars().first()
    if record:
        record.last_used_at = utcnow().replace(tzinfo=None)
        await session.commit()
    return record


# ==================== Cryptographic SBOM Signing & SLSA Provenance ====================

def _signing_key() -> bytes:
    return (settings.SECRET_KEY or "securechain-signing-key").encode("utf-8")


async def sign_sbom(
    session: AsyncSession,
    sbom_id: str | UUID,
    organization_id: str | UUID,
    signer: str,
    slsa_level: str = "SLSA_BUILD_L2",
) -> dict[str, Any] | None:
    sbom = await get_sbom(session, str(sbom_id), str(organization_id))
    if not sbom:
        return None
    components = await list_components(session, str(sbom.id), limit=5000, offset=0)
    project = await get_project_by_id(session, str(sbom.project_id))

    # Build deterministic canonical payload (excluding volatile timestamps)
    canonical_payload = {
        "sbom_id": str(sbom.id),
        "project_id": str(sbom.project_id),
        "project_name": project.name if project else "SecureChain Project",
        "format": sbom.format,
        "version": sbom.version,
        "components": sorted(
            [
                {"name": c.name, "version": c.version, "purl": c.purl, "license": c.license}
                for c in components
            ],
            key=lambda x: (x["name"] or "", x["version"] or ""),
        ),
    }
    raw = _canonical_json(canonical_payload)
    payload_sha256 = hashlib.sha256(raw).hexdigest()
    signature = hmac.new(_signing_key(), raw, hashlib.sha256).hexdigest()

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": f"sbom-{sbom.id}", "digest": {"sha256": payload_sha256}}],
        "predicate": {
            "buildDefinition": {"buildType": "https://securechain.local/sbom-attestation/v1"},
            "runDetails": {"builder": {"id": "https://securechain.local/builder/v1.1"}, "slsaLevel": slsa_level},
        },
    }

    sig_record = SbomSignature(
        sbom_id=sbom.id,
        organization_id=_as_uuid(organization_id),
        algorithm="HMAC-SHA256-DSSE",
        payload_sha256=payload_sha256,
        signature=signature,
        signer=signer,
        slsa_level=slsa_level,
        provenance=provenance,
    )
    session.add(sig_record)
    await session.commit()
    await session.refresh(sig_record)

    return {
        "signature_id": str(sig_record.id),
        "sbom_id": str(sbom.id),
        "algorithm": sig_record.algorithm,
        "payload_sha256": payload_sha256,
        "signature": signature,
        "signer": signer,
        "slsa_level": slsa_level,
        "provenance": provenance,
        "signed_at": sig_record.signed_at.isoformat() + "Z",
    }


async def verify_sbom_signature(
    session: AsyncSession,
    sbom_id: str | UUID,
    organization_id: str | UUID,
) -> dict[str, Any]:
    """Recompute canonical SBOM hash & HMAC signature and verify against latest stored signature."""
    sbom = await get_sbom(session, str(sbom_id), str(organization_id))
    if not sbom:
        return {"verified": False, "reason": "SBOM not found"}

    stmt = (
        select(SbomSignature)
        .where(SbomSignature.sbom_id == sbom.id, SbomSignature.organization_id == _as_uuid(organization_id))
        .order_by(SbomSignature.signed_at.desc())
    )
    latest = (await session.execute(stmt)).scalars().first()
    if not latest:
        return {"verified": False, "reason": "SBOM has not been signed yet."}

    components = await list_components(session, str(sbom.id), limit=5000, offset=0)
    project = await get_project_by_id(session, str(sbom.project_id))
    canonical_payload = {
        "sbom_id": str(sbom.id),
        "project_id": str(sbom.project_id),
        "project_name": project.name if project else "SecureChain Project",
        "format": sbom.format,
        "version": sbom.version,
        "components": sorted(
            [
                {"name": c.name, "version": c.version, "purl": c.purl, "license": c.license}
                for c in components
            ],
            key=lambda x: (x["name"] or "", x["version"] or ""),
        ),
    }
    raw = _canonical_json(canonical_payload)
    current_sha256 = hashlib.sha256(raw).hexdigest()
    expected_sig = hmac.new(_signing_key(), raw, hashlib.sha256).hexdigest()

    hash_match = hmac.compare_digest(current_sha256, latest.payload_sha256)
    sig_match = hmac.compare_digest(expected_sig, latest.signature)
    verified = hash_match and sig_match

    return {
        "verified": verified,
        "sbom_id": str(sbom.id),
        "signature_id": str(latest.id),
        "signer": latest.signer,
        "slsa_level": latest.slsa_level,
        "algorithm": latest.algorithm,
        "payload_sha256": current_sha256,
        "tampered": not verified,
        "reason": "Cryptographic signature & SLSA digest verified." if verified else "TAMPER DETECTED: SBOM components changed after signing.",
    }


# ==================== Auto-Fix Patch & PR Generator ====================

async def generate_autofix_patches(
    session: AsyncSession,
    sbom_id: str | UUID,
    organization_id: str | UUID,
) -> dict[str, Any] | None:
    sbom = await get_sbom(session, str(sbom_id), str(organization_id))
    if not sbom:
        return None

    rows = (
        await session.execute(
            select(Component, Vulnerability)
            .join(ComponentVulnerability, ComponentVulnerability.component_id == Component.id)
            .join(Vulnerability, ComponentVulnerability.vulnerability_id == Vulnerability.id)
            .where(Component.sbom_id == sbom.id)
        )
    ).all()

    patches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for comp, vuln in rows:
        meta = vuln.metadata_ or {}
        fixed_ver = meta.get("fixed_version")
        if not fixed_ver:
            continue
        key = (comp.name, fixed_ver)
        if key in seen:
            continue
        seen.add(key)

        purl = (comp.purl or "").lower()
        if "pkg:npm/" in purl:
            manifest = "package.json"
            diff = f'-  "{comp.name}": "{comp.version}"\n+  "{comp.name}": "^{fixed_ver}"'
        elif "pkg:golang/" in purl:
            manifest = "go.mod"
            diff = f"-  {comp.name} v{comp.version}\n+  {comp.name} v{fixed_ver}"
        elif "pkg:maven/" in purl:
            manifest = "pom.xml"
            diff = f"-  <version>{comp.version}</version> <!-- {comp.name} -->\n+  <version>{fixed_ver}</version> <!-- {comp.name} -->"
        else:
            manifest = "requirements.txt"
            diff = f"-{comp.name}=={comp.version}\n+{comp.name}>={fixed_ver}"

        patches.append(
            {
                "component_name": comp.name,
                "current_version": comp.version,
                "fixed_version": fixed_ver,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "in_kev": bool(meta.get("in_kev", False)),
                "target_manifest": manifest,
                "unified_diff": diff,
            }
        )

    pr_title = (
        f"chore(security): fix {len(patches)} vulnerable dependency(ies) via SecureChain Auto-Fix"
        if patches
        else "No automated patches required"
    )
    pr_body_lines = ["## SecureChain Automated Remediation PR", ""]
    for p in patches:
        pr_body_lines.append(
            f"- Upgrade **`{p['component_name']}`** `{p['current_version']}` → **`{p['fixed_version']}`** "
            f"(resolves `{p['cve_id']}`, {p['severity'].upper()}{', CISA KEV' if p['in_kev'] else ''})"
        )

    return {
        "sbom_id": str(sbom.id),
        "patch_count": len(patches),
        "patches": patches,
        "pull_request": {"title": pr_title, "body": "\n".join(pr_body_lines)},
        "generated_at": utcnow_iso(),
    }


# ==================== Webhooks ====================

async def create_webhook(
    session: AsyncSession,
    organization_id: str | UUID,
    name: str,
    url: str,
    events: list[str] | None = None,
) -> WebhookEndpoint:
    hook = WebhookEndpoint(
        organization_id=_as_uuid(organization_id),
        name=name,
        url=url,
        secret=f"whsec_{secrets.token_hex(24)}",
        events=events or ["kev.detected", "critical.cve", "threat.typosquatting", "compliance.failed"],
        is_active=True,
    )
    session.add(hook)
    await session.commit()
    await session.refresh(hook)
    return hook


async def list_webhooks(session: AsyncSession, organization_id: str | UUID) -> list[WebhookEndpoint]:
    stmt = (
        select(WebhookEndpoint)
        .where(WebhookEndpoint.organization_id == _as_uuid(organization_id))
        .order_by(WebhookEndpoint.created_at.desc())
    )
    return (await session.execute(stmt)).scalars().all()


async def delete_webhook(session: AsyncSession, webhook_id: str | UUID, organization_id: str | UUID) -> bool:
    stmt = select(WebhookEndpoint).where(
        WebhookEndpoint.id == _as_uuid(webhook_id),
        WebhookEndpoint.organization_id == _as_uuid(organization_id),
    )
    hook = (await session.execute(stmt)).scalars().first()
    if not hook:
        return False
    await session.delete(hook)
    await session.commit()
    return True


async def dispatch_webhook_event(
    session: AsyncSession,
    organization_id: str | UUID,
    event_type: str,
    payload: dict[str, Any],
) -> int:
    hooks = await list_webhooks(session, organization_id)
    delivered = 0
    body = _canonical_json({"event": event_type, "timestamp": utcnow_iso(), "data": payload})

    async with httpx.AsyncClient(timeout=3.0) as client:
        for hook in hooks:
            if not hook.is_active or (hook.events and event_type not in hook.events):
                continue
            sig = hmac.new(hook.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            try:
                await client.post(
                    hook.url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-SecureChain-Event": event_type,
                        "X-SecureChain-Signature-256": f"sha256={sig}",
                    },
                )
                hook.last_triggered_at = utcnow().replace(tzinfo=None)
                delivered += 1
            except Exception:
                continue
    if delivered:
        await session.commit()
    return delivered


# ==================== One-Click Regulatory Audit Evidence Bundle ====================

async def build_audit_evidence_bundle(
    session: AsyncSession,
    organization_id: str | UUID,
    sbom_id: str | UUID,
    signer: str,
) -> dict[str, Any] | None:
    sbom = await get_sbom(session, str(sbom_id), str(organization_id))
    if not sbom:
        return None
    components = await list_components(session, str(sbom.id), limit=5000, offset=0)
    project = await get_project_by_id(session, str(sbom.project_id))
    project_name = project.name if project else "SecureChain Project"

    cyclonedx = export_cyclonedx(sbom, components, project_name)
    completeness = evaluate_sbom_completeness(sbom, components)
    risk = await calculate_sbom_risk(session, sbom.id)
    vex_statements = await list_vex_statements(session, organization_id, sbom_id=sbom.id)
    openvex = export_openvex(str(sbom.id), vex_statements, author=signer)
    compliance = await evaluate_organization_compliance(session, organization_id, sbom_id=sbom.id)
    signature = await sign_sbom(session, sbom.id, organization_id, signer=signer)

    return {
        "bundle_version": "1.0",
        "generated_at": utcnow_iso(),
        "project": {"id": str(sbom.project_id), "name": project_name},
        "risk_summary": risk,
        "cisa_2026_completeness": completeness,
        "regulatory_compliance": compliance,
        "cryptographic_attestation": signature,
        "sbom_cyclonedx": cyclonedx,
        "vex_openvex": openvex,
    }
