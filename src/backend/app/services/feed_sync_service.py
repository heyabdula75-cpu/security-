"""
Live Global Threat Intelligence Feed Syncer:
- CISA KEV (Known Exploited Vulnerabilities) live JSON feed sync
- FIRST EPSS live exploit probability lookup
- OpenSSF Scorecard live repository health lookup
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.services.intel_service import EPSS_API_URL, KNOWN_KEV_CVES
from app.utils.time_utils import utcnow_iso

logger = logging.getLogger("app.feed_sync")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENSSF_SCORECARD_URL = "https://api.securityscorecards.dev/projects/github.com/{repo}"


async def sync_cisa_kev_catalog(timeout: float = 5.0) -> dict[str, Any]:
    """Fetch live CISA KEV catalog and merge all CVEs into KNOWN_KEV_CVES."""
    before = len(KNOWN_KEV_CVES)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(CISA_KEV_FEED_URL)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities") or []
                for item in vulns:
                    cve = item.get("cveID")
                    if cve:
                        KNOWN_KEV_CVES.add(str(cve).upper())
                return {
                    "source": "cisa.gov-live",
                    "status": "synced",
                    "catalog_version": data.get("catalogVersion"),
                    "total_kev_cves": len(KNOWN_KEV_CVES),
                    "newly_added": len(KNOWN_KEV_CVES) - before,
                    "synced_at": utcnow_iso(),
                }
    except Exception as exc:
        logger.debug("CISA KEV live feed unreachable (%s); retaining local baseline.", exc)

    return {
        "source": "local-baseline-fallback",
        "status": "offline_fallback",
        "total_kev_cves": len(KNOWN_KEV_CVES),
        "newly_added": 0,
        "synced_at": utcnow_iso(),
    }


async def fetch_live_epss_scores(cve_ids: list[str], timeout: float = 4.0) -> dict[str, dict[str, float]]:
    """Query FIRST.org EPSS API for live 30-day exploitation probabilities."""
    clean_ids = [c.upper().strip() for c in cve_ids if c.upper().startswith("CVE-")]
    if not clean_ids:
        return {}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": ",".join(clean_ids[:50])})
            if resp.status_code == 200:
                out: dict[str, dict[str, float]] = {}
                for row in resp.json().get("data") or []:
                    out[row["cve"]] = {
                        "epss": float(row.get("epss", 0.0)),
                        "percentile": float(row.get("percentile", 0.0)),
                    }
                return out
    except Exception as exc:
        logger.debug("FIRST EPSS API unreachable (%s).", exc)
    return {}


async def fetch_openssf_scorecard(repo: str, timeout: float = 4.0) -> dict[str, Any]:
    """Query OpenSSF Scorecard API for a GitHub repository (owner/repo)."""
    clean_repo = repo.strip().strip("/")
    if clean_repo.startswith("https://github.com/"):
        clean_repo = clean_repo[len("https://github.com/"):]
    if "/" not in clean_repo:
        raise ValueError("Repository must be in 'owner/repo' format.")

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(OPENSSF_SCORECARD_URL.format(repo=clean_repo))
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "repo": clean_repo,
                    "source": "openssf-live",
                    "score": data.get("score"),
                    "date": data.get("date"),
                    "checks": [
                        {"name": c.get("name"), "score": c.get("score"), "reason": c.get("reason")}
                        for c in (data.get("checks") or [])[:10]
                    ],
                }
    except Exception as exc:
        logger.debug("OpenSSF Scorecard unreachable (%s).", exc)

    return {
        "repo": clean_repo,
        "source": "offline-unavailable",
        "score": None,
        "checks": [],
        "note": "OpenSSF Scorecard API is currently unreachable from this network.",
    }
