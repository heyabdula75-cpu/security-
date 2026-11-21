"""
Enterprise Powerhouse API Routes:
- AI Security Copilot (/assistant/query)
- Deep AI-BOM / Pickle & Model Scanner (/ai-bom/scan)
- Scoped API Keys (/auth/api-keys)
- Cryptographic SBOM Signing & Tamper Verification (/sboms/{id}/sign, /verify)
- Auto-Fix Patch & PR Diff Generator (/sboms/{id}/autofix)
- One-Click Audit Evidence Bundle (/sboms/{id}/audit-bundle)
- Enterprise Webhooks (/webhooks)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.copilot_service import query_security_copilot, scan_ai_bom_artifact
from app.services.monitor_service import evaluate_k8s_runtime_drift, run_continuous_rescan_cycle
from app.services.enterprise_service import (
    build_audit_evidence_bundle,
    create_api_key,
    create_webhook,
    delete_webhook,
    generate_autofix_patches,
    list_api_keys,
    list_webhooks,
    revoke_api_key,
    sign_sbom,
    verify_sbom_signature,
)

router = APIRouter()


class CopilotQueryRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=2000)


class AiBomScanRequest(BaseModel):
    filename: str
    content_text: str | None = None
    content_base64: str | None = None


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    scopes: list[str] = Field(default_factory=lambda: ["sbom:read", "scan:write", "compliance:read"])


class WebhookCreateRequest(BaseModel):
    name: str
    url: str
    events: list[str] = Field(default_factory=lambda: ["kev.detected", "critical.cve", "threat.typosquatting"])


class SignSbomRequest(BaseModel):
    slsa_level: str = "SLSA_BUILD_L2"


async def _get_org_and_user(current_user: dict, db: AsyncSession) -> tuple[str, str, str]:
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = await get_user_by_id(db, user_id)
    if not user or not user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User or organization not found")
    return str(user.organization_id), str(user.id), (user.email or "SecureChain Operator")


@router.post("/assistant/query")
async def ask_security_copilot(
    payload: CopilotQueryRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Query the live data-grounded AI Security Copilot."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    result = await query_security_copilot(db, org_id, payload.question)
    return {"success": True, "data": result}


@router.post("/ai-bom/scan")
async def scan_ai_artifact(
    payload: AiBomScanRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Statically scan pickle weights, HuggingFace config.json, Modelfile, or Python ML loader code."""
    await _get_org_and_user(current_user, db)
    result = scan_ai_bom_artifact(payload.filename, payload.content_text, payload.content_base64)
    return {"success": True, "data": result}


@router.post("/auth/api-keys", status_code=201)
async def create_org_api_key(
    payload: ApiKeyCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a real scoped API key for CLI/CI pipelines. Plaintext key is shown once."""
    org_id, user_id, _ = await _get_org_and_user(current_user, db)
    record, plaintext = await create_api_key(db, org_id, user_id, payload.name, payload.scopes)
    return {
        "success": True,
        "data": {
            "id": str(record.id),
            "name": record.name,
            "key_prefix": record.key_prefix,
            "api_key": plaintext,
            "scopes": record.scopes,
            "created_at": record.created_at.isoformat() + "Z",
        },
    }


@router.get("/auth/api-keys")
async def list_org_api_keys(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scoped API keys for the authenticated organization."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    keys = await list_api_keys(db, org_id)
    return {
        "success": True,
        "data": [
            {
                "id": str(k.id),
                "name": k.name,
                "key_prefix": k.key_prefix,
                "scopes": k.scopes,
                "is_active": k.is_active,
                "last_used_at": k.last_used_at.isoformat() + "Z" if k.last_used_at else None,
                "created_at": k.created_at.isoformat() + "Z",
            }
            for k in keys
        ],
    }


@router.delete("/auth/api-keys/{key_id}")
async def revoke_org_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    revoked = await revoke_api_key(db, key_id, org_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return {"success": True, "message": "API key revoked"}


@router.post("/sboms/{sbom_id}/sign", status_code=201)
async def sign_sbom_route(
    sbom_id: str,
    payload: SignSbomRequest | None = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cryptographically sign an SBOM with DSSE HMAC-SHA256 & SLSA provenance metadata."""
    org_id, _, email = await _get_org_and_user(current_user, db)
    slsa = payload.slsa_level if payload else "SLSA_BUILD_L2"
    result = await sign_sbom(db, sbom_id, org_id, signer=email, slsa_level=slsa)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")
    return {"success": True, "data": result}


@router.post("/sboms/{sbom_id}/verify")
async def verify_sbom_route(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify cryptographic signature & tamper status of a signed SBOM."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    result = await verify_sbom_signature(db, sbom_id, org_id)
    return {"success": True, "data": result}


@router.get("/sboms/{sbom_id}/autofix")
async def autofix_sbom_route(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate automated manifest patch diffs and PR payload to remediate known vulnerabilities."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    result = await generate_autofix_patches(db, sbom_id, org_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")
    return {"success": True, "data": result}


@router.get("/sboms/{sbom_id}/audit-bundle")
async def export_audit_bundle(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export one-click signed Regulatory Audit Evidence Bundle (Compliance + CycloneDX + OpenVEX + SLSA Signature)."""
    org_id, _, email = await _get_org_and_user(current_user, db)
    bundle = await build_audit_evidence_bundle(db, org_id, sbom_id, signer=email)
    if not bundle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")
    return {"success": True, "data": bundle}


@router.post("/webhooks", status_code=201)
async def create_org_webhook(
    payload: WebhookCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register an HMAC-signed webhook endpoint for real-time security alerts."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    hook = await create_webhook(db, org_id, payload.name, payload.url, payload.events)
    return {
        "success": True,
        "data": {
            "id": str(hook.id),
            "name": hook.name,
            "url": hook.url,
            "secret": hook.secret,
            "events": hook.events,
            "is_active": hook.is_active,
        },
    }


@router.get("/webhooks")
async def list_org_webhooks(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List configured webhooks."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    hooks = await list_webhooks(db, org_id)
    return {
        "success": True,
        "data": [
            {
                "id": str(h.id),
                "name": h.name,
                "url": h.url,
                "events": h.events,
                "is_active": h.is_active,
                "last_triggered_at": h.last_triggered_at.isoformat() + "Z" if h.last_triggered_at else None,
            }
            for h in hooks
        ],
    }


@router.delete("/webhooks/{webhook_id}")
async def delete_org_webhook(
    webhook_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook endpoint."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    deleted = await delete_webhook(db, webhook_id, org_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return {"success": True, "message": "Webhook deleted"}


class K8sDriftRequest(BaseModel):
    workloads: list[dict]


@router.post("/monitor/rescan")
async def trigger_continuous_rescan(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run an immediate continuous zero-day rescan across all org SBOMs and fire webhook alerts."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    summary = await run_continuous_rescan_cycle(db, org_id)
    return {"success": True, "data": summary}


@router.post("/runtime/k8s-drift")
async def check_k8s_runtime_drift(
    payload: K8sDriftRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compare running Kubernetes pod images against signed CI/CD SBOMs to detect shadow/drifted containers."""
    org_id, _, _ = await _get_org_and_user(current_user, db)
    report = await evaluate_k8s_runtime_drift(db, org_id, payload.workloads)
    return {"success": True, "data": report}
