"""
Tests for Build #1, #2, and #3:
- Live CISA KEV sync graceful behavior
- GitHub App HMAC-SHA256 webhook verification & Auto-Fix PR preview
- OIDC SSO authorization URL builder (Google, Entra, Okta)
- Prometheus /metrics exposition format
- Branded HTML/PDF Executive Compliance Dossier
"""
import hashlib
import hmac
import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.services.feed_sync_service import sync_cisa_kev_catalog
from app.services.github_integration import (
    create_github_autofix_pr,
    handle_github_webhook_event,
    verify_github_webhook_signature,
)
from app.services.platform_ops_service import (
    build_oidc_authorize_url,
    render_executive_report_html,
    render_prometheus_metrics,
)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as db_session:
        yield db_session

    await engine.dispose()


async def test_cisa_kev_sync_returns_valid_summary():
    res = await sync_cisa_kev_catalog(timeout=1.0)
    assert res["total_kev_cves"] >= 5
    assert res["status"] in {"synced", "offline_fallback"}


async def test_github_webhook_hmac_and_autofix_pr():
    secret = "super-secret-webhook-key"
    body = json.dumps({
        "action": "opened",
        "repository": {"full_name": "acme/payments"},
        "pull_request": {"number": 42, "head": {"sha": "abc123", "ref": "feat/deps"}, "base": {"ref": "main"}},
    }).encode("utf-8")
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    assert verify_github_webhook_signature(body, valid_sig, secret) is True
    assert verify_github_webhook_signature(body, "sha256=deadbeef", secret) is False

    evt = handle_github_webhook_event("pull_request", json.loads(body))
    assert evt["pr_number"] == 42
    assert evt["recommended_action"] == "trigger_sbom_pr_gate"

    pr_preview = await create_github_autofix_pr(
        "acme/payments",
        "main",
        {"sbom_id": "12345678-aaaa", "patch_count": 1, "patches": [], "pull_request": {"title": "Fix Log4j", "body": "Upgrade"}},
    )
    assert pr_preview["mode"] == "dry_run_preview"
    assert pr_preview["branch"] == "securechain/autofix-12345678"


def test_oidc_sso_and_executive_html_report():
    google = build_oidc_authorize_url("google", "cid-1", "https://app.example.com/cb")
    assert "accounts.google.com" in google["authorization_url"]

    okta = build_oidc_authorize_url("okta", "cid-2", "https://app.example.com/cb", domain="acme.okta.com")
    assert "acme.okta.com" in okta["authorization_url"]

    html_doc = render_executive_report_html({
        "project": {"name": "Payments Core"},
        "generated_at": "2026-11-21T00:00:00Z",
        "risk_summary": {"overall_score": 42.0, "risk_grade": "C", "kev_count": 0},
        "regulatory_compliance": {"overall_compliance_score": 88.5, "overall_grade": "B", "frameworks": []},
        "cisa_2026_completeness": {"completeness_score": 92.0, "grade": "A"},
        "cryptographic_attestation": {"algorithm": "HMAC-SHA256-DSSE", "slsa_level": "SLSA_BUILD_L3", "signer": "ciso@acme.io", "payload_sha256": "abc", "signature": "sig"},
    })
    assert "SecureChain Executive Audit Dossier" in html_doc
    assert "Payments Core" in html_doc
    assert "SLSA_BUILD_L3" in html_doc


async def test_prometheus_metrics_exposition(session: AsyncSession):
    metrics = await render_prometheus_metrics(session)
    assert "securechain_up 1" in metrics
    assert "securechain_sboms_total 0" in metrics
    assert "securechain_threats_open_total 0" in metrics
