"""
Fortune 500 Production & Platform Operations Services:
- OIDC SSO Authorization URL builder (Okta, Microsoft Entra ID, Google Workspace)
- Prometheus /metrics exposition format
- Branded HTML/Print-to-PDF Executive Compliance & Security Dossier
"""
from __future__ import annotations

import html
import secrets
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey, Sbom, ThreatDetection, VexStatement, Vulnerability

OIDC_PROVIDERS: dict[str, dict[str, str]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "scope": "openid email profile",
    },
    "entra": {
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "scope": "openid email profile",
    },
    "okta": {
        "authorize_url": "https://{domain}/oauth2/default/v1/authorize",
        "scope": "openid email profile groups",
    },
}


def build_oidc_authorize_url(
    provider: str,
    client_id: str,
    redirect_uri: str,
    domain: str | None = None,
) -> dict[str, str]:
    key = provider.lower().strip()
    if key not in OIDC_PROVIDERS:
        raise ValueError(f"Unsupported OIDC provider '{provider}'. Supported: google, entra, okta.")

    base = OIDC_PROVIDERS[key]["authorize_url"]
    if "{domain}" in base:
        if not domain:
            raise ValueError("Okta OIDC requires a 'domain' parameter (e.g. your-org.okta.com).")
        base = base.format(domain=domain.strip())

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(16)
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": OIDC_PROVIDERS[key]["scope"],
            "state": state,
            "nonce": nonce,
        }
    )
    return {"provider": key, "state": state, "nonce": nonce, "authorization_url": f"{base}?{query}"}


async def render_prometheus_metrics(session: AsyncSession) -> str:
    """Render live platform counters in Prometheus text exposition format."""
    sboms_total = (await session.scalar(select(func.count(Sbom.id)))) or 0
    vulns_total = (await session.scalar(select(func.count(Vulnerability.id)))) or 0
    threats_open = (
        await session.scalar(select(func.count(ThreatDetection.id)).where(ThreatDetection.status == "open"))
    ) or 0
    vex_total = (await session.scalar(select(func.count(VexStatement.id)))) or 0
    api_keys_active = (
        await session.scalar(select(func.count(ApiKey.id)).where(ApiKey.is_active.is_(True)))
    ) or 0

    lines = [
        "# HELP securechain_up SecureChain API availability (1 = up).",
        "# TYPE securechain_up gauge",
        "securechain_up 1",
        "# HELP securechain_sboms_total Total SBOMs stored.",
        "# TYPE securechain_sboms_total gauge",
        f"securechain_sboms_total {sboms_total}",
        "# HELP securechain_vulnerabilities_total Total unique CVEs tracked.",
        "# TYPE securechain_vulnerabilities_total gauge",
        f"securechain_vulnerabilities_total {vulns_total}",
        "# HELP securechain_threats_open_total Active open supply-chain threats.",
        "# TYPE securechain_threats_open_total gauge",
        f"securechain_threats_open_total {threats_open}",
        "# HELP securechain_vex_statements_total Total VEX attestations.",
        "# TYPE securechain_vex_statements_total gauge",
        f"securechain_vex_statements_total {vex_total}",
        "# HELP securechain_api_keys_active_total Active scoped CI/CD API keys.",
        "# TYPE securechain_api_keys_active_total gauge",
        f"securechain_api_keys_active_total {api_keys_active}",
        "",
    ]
    return "\n".join(lines)


def render_executive_report_html(bundle: dict[str, Any]) -> str:
    """Render a branded, print-to-PDF ready Executive Security & Compliance Dossier."""
    project = html.escape(str((bundle.get("project") or {}).get("name", "SecureChain Project")))
    risk = bundle.get("risk_summary") or {}
    comp = bundle.get("regulatory_compliance") or {}
    cisa = bundle.get("cisa_2026_completeness") or {}
    sig = bundle.get("cryptographic_attestation") or {}
    frameworks = comp.get("frameworks") or []

    fw_rows = "".join(
        f"<tr><td><strong>{html.escape(f['name'])}</strong></td>"
        f"<td>{f['score']}%</td><td><span class='badge'>{html.escape(f['grade'])}</span></td>"
        f"<td>{f['passed_controls']}/{f['total_controls']} passed</td></tr>"
        for f in frameworks
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SecureChain Executive Audit Report — {project}</title>
<style>
  body {{ font-family: Inter, -apple-system, BlinkMacSystemFont, sans-serif; color: #0f172a; margin: 2rem auto; max-width: 900px; line-height: 1.5; }}
  .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom: 3px solid #0ea5e9; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  .kpi-grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }}
  .kpi {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; }}
  .kpi-val {{ font-size: 1.75rem; font-weight: 800; color: #0f172a; }}
  .kpi-lbl {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ text-align: left; padding: 0.65rem; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f1f5f9; font-size: 0.8rem; text-transform: uppercase; }}
  .badge {{ background: #0ea5e9; color: white; padding: 0.15rem 0.55rem; border-radius: 999px; font-weight: 700; font-size: 0.8rem; }}
  .sig-box {{ background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
  @media print {{ .no-print {{ display: none; }} }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin:0;">🛡️ SecureChain Executive Audit Dossier</h1>
      <div style="color:#475569;">Project: <strong>{project}</strong> · Generated: {html.escape(str(bundle.get('generated_at', '')))}</div>
    </div>
    <button class="no-print" onclick="window.print()" style="padding:0.5rem 1rem; background:#0ea5e9; color:#fff; border:none; border-radius:6px; cursor:pointer; font-weight:600;">🖨️ Save as PDF</button>
  </div>

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">Contextual Risk Score</div><div class="kpi-val">{risk.get('overall_score', 0)}/100 ({html.escape(str(risk.get('risk_grade', 'A')))})</div></div>
    <div class="kpi"><div class="kpi-lbl">Compliance Posture</div><div class="kpi-val">{comp.get('overall_compliance_score', 0)}% ({html.escape(str(comp.get('overall_grade', 'A')))})</div></div>
    <div class="kpi"><div class="kpi-lbl">CISA 2026 SBOM</div><div class="kpi-val">{cisa.get('completeness_score', 0)}% ({html.escape(str(cisa.get('grade', 'A')))})</div></div>
    <div class="kpi"><div class="kpi-lbl">Active CISA KEV</div><div class="kpi-val">{risk.get('kev_count', 0)}</div></div>
  </div>

  <h2>Regulatory Compliance Breakdown</h2>
  <table>
    <thead><tr><th>Framework</th><th>Score</th><th>Grade</th><th>Controls</th></tr></thead>
    <tbody>{fw_rows}</tbody>
  </table>

  <h2>Cryptographic Provenance &amp; SLSA Attestation</h2>
  <div class="sig-box">
    Algorithm: {html.escape(str(sig.get('algorithm', 'HMAC-SHA256-DSSE')))} · SLSA Level: {html.escape(str(sig.get('slsa_level', 'SLSA_BUILD_L2')))}<br/>
    Signer: {html.escape(str(sig.get('signer', 'SecureChain')))}<br/>
    Payload SHA-256: {html.escape(str(sig.get('payload_sha256', '—')))}<br/>
    Signature: {html.escape(str(sig.get('signature', '—')))}
  </div>
</body>
</html>"""
