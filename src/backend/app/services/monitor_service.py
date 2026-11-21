"""
Continuous Zero-Day Monitor & Kubernetes Runtime Drift Service:
- Re-scans stored SBOMs against latest vulnerability & threat intelligence and dispatches webhooks
- Compares running Kubernetes container workloads against signed CI/CD SBOMs to detect unsigned/drifted pods
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Project, Sbom, SbomSignature
from app.services.enterprise_service import dispatch_webhook_event
from app.services.threat_service import build_threats_for_sbom
from app.services.vulnerability_service import scan_sbom_vulnerabilities
from app.utils.time_utils import utcnow_iso


def _as_uuid(value: str | UUID) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


async def run_continuous_rescan_cycle(
    session: AsyncSession,
    organization_id: str | UUID,
    use_live_osv: bool = True,
) -> dict[str, Any]:
    """Re-scan every SBOM in the organization and dispatch webhooks for KEV or critical exposures."""
    org_uuid = _as_uuid(organization_id)
    sboms = (
        await session.execute(
            select(Sbom).join(Project).where(Project.organization_id == org_uuid)
        )
    ).scalars().all()

    rescanned = 0
    total_kev = 0
    total_new_vulns = 0
    total_threats = 0
    webhooks_dispatched = 0

    for sbom in sboms:
        scan = await scan_sbom_vulnerabilities(session, str(sbom.id), org_uuid, use_live_osv=use_live_osv)
        threats = await build_threats_for_sbom(session, sbom.id)
        rescanned += 1
        if scan:
            total_kev += scan.get("kev_findings_count", 0)
            total_new_vulns += scan.get("new_findings_count", 0)
            if scan.get("kev_findings_count", 0) > 0:
                webhooks_dispatched += await dispatch_webhook_event(
                    session,
                    org_uuid,
                    "kev.detected",
                    {"sbom_id": str(sbom.id), "kev_count": scan["kev_findings_count"], "risk_score": scan["risk_score"]},
                )
        total_threats += len(threats)

    return {
        "organization_id": str(org_uuid),
        "sboms_rescanned": rescanned,
        "new_vulnerabilities_found": total_new_vulns,
        "active_kev_findings": total_kev,
        "open_threats": total_threats,
        "webhooks_dispatched": webhooks_dispatched,
        "completed_at": utcnow_iso(),
    }


async def evaluate_k8s_runtime_drift(
    session: AsyncSession,
    organization_id: str | UUID,
    workloads: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compare running Kubernetes container workloads against organization SBOMs and SLSA signatures.
    Each workload dict: {namespace, pod, image, tag (optional), digest (optional)}.
    """
    org_uuid = _as_uuid(organization_id)
    sboms = (
        await session.execute(
            select(Sbom)
            .options(selectinload(Sbom.components))
            .join(Project)
            .where(Project.organization_id == org_uuid)
        )
    ).scalars().all()

    signed_sbom_ids = set(
        (
            await session.execute(
                select(SbomSignature.sbom_id).where(SbomSignature.organization_id == org_uuid)
            )
        ).scalars().all()
    )

    # Index known container images from SBOMs
    known_images: dict[str, list[tuple[Sbom, str]]] = {}
    for sbom in sboms:
        for comp in sbom.components:
            if (comp.type or "").lower() in {"container", "oci", "application"}:
                known_images.setdefault(comp.name.lower(), []).append((sbom, (comp.version or "").lower()))

    findings: list[dict[str, Any]] = []
    verified_count = 0
    drifted_count = 0
    untracked_count = 0

    for w in workloads:
        raw_image = str(w.get("image") or "")
        if ":" in raw_image and not raw_image.endswith(":"):
            img_name, img_tag = raw_image.rsplit(":", 1)
        else:
            img_name, img_tag = raw_image, str(w.get("tag") or "latest")

        matches = known_images.get(img_name.lower(), [])
        if not matches:
            untracked_count += 1
            findings.append(
                {
                    "namespace": w.get("namespace", "default"),
                    "pod": w.get("pod", "unknown"),
                    "image": f"{img_name}:{img_tag}",
                    "status": "untracked_shadow_container",
                    "severity": "high",
                    "signed": False,
                    "detail": f"Running container '{img_name}:{img_tag}' has no matching CI/CD SBOM in SecureChain.",
                }
            )
            continue

        exact_match = next(((s, ver) for s, ver in matches if ver == img_tag.lower()), None)
        if not exact_match:
            drifted_count += 1
            expected_versions = sorted({ver for _, ver in matches})
            findings.append(
                {
                    "namespace": w.get("namespace", "default"),
                    "pod": w.get("pod", "unknown"),
                    "image": f"{img_name}:{img_tag}",
                    "status": "version_drift",
                    "severity": "medium",
                    "signed": False,
                    "detail": f"Runtime tag '{img_tag}' drifted from tracked SBOM version(s): {expected_versions}.",
                }
            )
            continue

        matched_sbom, _ = exact_match
        is_signed = matched_sbom.id in signed_sbom_ids
        if is_signed:
            verified_count += 1
            status_str = "verified_signed"
            sev = "ok"
            detail = "Running image matches a cryptographically signed CI/CD SBOM."
        else:
            drifted_count += 1
            status_str = "unsigned_sbom"
            sev = "medium"
            detail = "Running image matches an SBOM, but the SBOM lacks a SLSA cryptographic signature."

        findings.append(
            {
                "namespace": w.get("namespace", "default"),
                "pod": w.get("pod", "unknown"),
                "image": f"{img_name}:{img_tag}",
                "sbom_id": str(matched_sbom.id),
                "status": status_str,
                "severity": sev,
                "signed": is_signed,
                "detail": detail,
            }
        )

    return {
        "total_workloads": len(workloads),
        "verified_signed": verified_count,
        "drifted_or_unsigned": drifted_count,
        "untracked_shadow": untracked_count,
        "findings": findings,
        "evaluated_at": utcnow_iso(),
    }
