"""
Native GitHub App Webhook Receiver & Automated Fix Pull Request Engine.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx

from app.utils.time_utils import utcnow_iso


def verify_github_webhook_signature(payload_bytes: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify GitHub X-Hub-Signature-256 HMAC header in constant time."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def handle_github_webhook_event(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize incoming GitHub App pull_request / push webhook events for automated SBOM scanning."""
    repo = (payload.get("repository") or {}).get("full_name", "unknown/repo")
    if event_type == "pull_request":
        pr = payload.get("pull_request") or {}
        return {
            "accepted": True,
            "event": "pull_request",
            "action": payload.get("action"),
            "repository": repo,
            "pr_number": pr.get("number"),
            "head_sha": (pr.get("head") or {}).get("sha"),
            "head_ref": (pr.get("head") or {}).get("ref"),
            "base_ref": (pr.get("base") or {}).get("ref"),
            "recommended_action": "trigger_sbom_pr_gate",
            "received_at": utcnow_iso(),
        }
    if event_type == "push":
        return {
            "accepted": True,
            "event": "push",
            "repository": repo,
            "ref": payload.get("ref"),
            "head_sha": payload.get("after"),
            "recommended_action": "trigger_continuous_sbom_scan",
            "received_at": utcnow_iso(),
        }
    return {
        "accepted": True,
        "event": event_type,
        "repository": repo,
        "recommended_action": "ignored",
        "received_at": utcnow_iso(),
    }


async def create_github_autofix_pr(
    repo_full_name: str,
    base_branch: str,
    autofix_result: dict[str, Any],
    github_token: str | None = None,
) -> dict[str, Any]:
    """
    Build a GitHub Auto-Fix PR specification from /sboms/{id}/autofix output.
    If `github_token` is supplied, attempts to open the Pull Request via GitHub REST API;
    otherwise returns a dry-run preview payload ready for GitHub App execution.
    """
    pr_meta = autofix_result.get("pull_request") or {}
    branch_name = f"securechain/autofix-{autofix_result.get('sbom_id', 'sbom')[:8]}"
    pr_payload = {
        "title": pr_meta.get("title", "chore(security): SecureChain Auto-Fix"),
        "body": pr_meta.get("body", ""),
        "head": branch_name,
        "base": base_branch,
    }

    if not github_token:
        return {
            "mode": "dry_run_preview",
            "repository": repo_full_name,
            "branch": branch_name,
            "patch_count": autofix_result.get("patch_count", 0),
            "pr_payload": pr_payload,
            "patches": autofix_result.get("patches", []),
        }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                f"https://api.github.com/repos/{repo_full_name}/pulls",
                json=pr_payload,
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            return {
                "mode": "live_github_api",
                "repository": repo_full_name,
                "http_status": resp.status_code,
                "pr_url": resp.json().get("html_url") if resp.status_code in {200, 201} else None,
                "response": resp.json(),
            }
    except Exception as exc:
        return {
            "mode": "live_github_api_error",
            "repository": repo_full_name,
            "error": str(exc),
            "pr_payload": pr_payload,
        }
