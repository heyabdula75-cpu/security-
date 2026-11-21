"""
Integrations, Live Threat Feeds, OIDC SSO, and Executive Report API routes.
"""
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.enterprise_service import build_audit_evidence_bundle, generate_autofix_patches
from app.services.feed_sync_service import fetch_openssf_scorecard, sync_cisa_kev_catalog
from app.services.github_integration import (
    create_github_autofix_pr,
    handle_github_webhook_event,
    verify_github_webhook_signature,
)
from app.services.platform_ops_service import build_oidc_authorize_url, render_executive_report_html

router = APIRouter()


class GitHubAutoFixPrRequest(BaseModel):
    sbom_id: str
    repo_full_name: str
    base_branch: str = "main"
    github_token: str | None = None


async def _get_org_and_email(current_user: dict, db: AsyncSession) -> tuple[str, str]:
    org_id = current_user.get("organization_id")
    user_id = current_user.get("sub")
    if org_id:
        return str(org_id), str(current_user.get("email") or "api-key@securechain.local")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = await get_user_by_id(db, user_id)
    if not user or not user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User or organization not found")
    return str(user.organization_id), (user.email or "SecureChain Operator")


@router.post("/intel/sync")
async def sync_threat_intel_feeds(
    current_user: dict = Depends(get_current_user),
):
    """Sync live CISA KEV catalog into the platform intelligence cache."""
    result = await sync_cisa_kev_catalog()
    return {"success": True, "data": result}


@router.get("/intel/scorecard")
async def get_openssf_scorecard(
    repo: str = Query(..., description="GitHub repository in owner/repo format"),
    current_user: dict = Depends(get_current_user),
):
    """Fetch live OpenSSF Scorecard health metrics for a GitHub dependency."""
    try:
        data = await fetch_openssf_scorecard(repo)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"success": True, "data": data}


@router.post("/integrations/github/webhook")
async def github_app_webhook(
    request: Request,
    x_github_event: str = Header(default="ping", alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
):
    """Native GitHub App webhook receiver with HMAC-SHA256 signature verification."""
    raw_body = await request.body()
    secret = settings.SECRET_KEY or "securechain-github-secret"
    if x_hub_signature_256 and not verify_github_webhook_signature(raw_body, x_hub_signature_256, secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid GitHub webhook signature")

    payload = await request.json()
    result = handle_github_webhook_event(x_github_event, payload)
    return {"success": True, "data": result}


@router.post("/integrations/github/autofix-pr")
async def open_github_autofix_pr(
    payload: GitHubAutoFixPrRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate or open a GitHub Auto-Fix Pull Request for vulnerable SBOM dependencies."""
    org_id, _ = await _get_org_and_email(current_user, db)
    autofix = await generate_autofix_patches(db, payload.sbom_id, org_id)
    if not autofix:
        raise HTTPException(status_code=404, detail="SBOM not found")
    res = await create_github_autofix_pr(
        payload.repo_full_name,
        payload.base_branch,
        autofix,
        github_token=payload.github_token,
    )
    return {"success": True, "data": res}


@router.get("/auth/oidc/authorize")
async def oidc_sso_authorize(
    provider: str = Query(..., description="google, entra, or okta"),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    domain: str | None = Query(default=None),
):
    """Build an enterprise OIDC SSO authorization URL (Okta, Microsoft Entra ID, Google Workspace)."""
    try:
        data = build_oidc_authorize_url(provider, client_id, redirect_uri, domain=domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"success": True, "data": data}


@router.get("/sboms/{sbom_id}/executive-report", response_class=HTMLResponse)
async def get_executive_html_report(
    sbom_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a branded, print-to-PDF ready Executive Security & Compliance Dossier."""
    org_id, email = await _get_org_and_email(current_user, db)
    bundle = await build_audit_evidence_bundle(db, org_id, sbom_id, signer=email)
    if not bundle:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return HTMLResponse(content=render_executive_report_html(bundle))
