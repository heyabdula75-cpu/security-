"""
Supply Chain Threat Detection Service:
- Typosquatting & Combosquatting detection (Damerau-Levenshtein distance vs. top registry packages)
- Dependency Confusion detection (private/internal naming collision checks)
- Behavioral / Install-Script & Malware heuristics
- Copyleft License & AI/ML Model Supply Chain risk detection
- Persisted ThreatDetection records with triage workflow
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Component, Project, Sbom, ThreatDetection
from app.utils.time_utils import utcnow_iso

# Curated high-target packages frequently targeted by typosquatting/combosquatting attacks
POPULAR_PACKAGES: dict[str, set[str]] = {
    "pypi": {
        "requests", "urllib3", "numpy", "pandas", "scipy", "fastapi", "django", "flask",
        "sqlalchemy", "pydantic", "pytest", "boto3", "cryptography", "pillow", "torch",
        "tensorflow", "transformers", "langchain", "openai", "httpx", "aiohttp", "colorama",
        "beautifulsoup4", "scikit-learn", "setuptools", "pyyaml", "jinja2", "celery", "redis",
    },
    "npm": {
        "lodash", "react", "react-dom", "express", "axios", "moment", "typescript", "webpack",
        "next", "vue", "angular", "chalk", "commander", "dotenv", "eslint", "prettier", "jest",
        "uuid", "semver", "jsonwebtoken", "bcrypt", "mongoose", "prisma", "tailwindcss", "vite",
    },
    "maven": {
        "log4j-core", "spring-core", "spring-boot", "jackson-databind", "guava", "commons-io",
        "commons-lang3", "slf4j-api", "junit", "netty-all", "hibernate-core",
    },
    "golang": {
        "gin", "echo", "cobra", "viper", "logrus", "zap", "protobuf", "grpc",
    },
}

COMBO_AFFIXES = ("-dev", "-py", "-js", "-official", "-sdk", "-util", "-utils", "-core", "py-", "node-", "get-")
INTERNAL_PATTERNS = ("internal-", "corp-", "private-", "-internal", "-private", "-corp")
STRONG_COPYLEFT = ("GPL", "AGPL", "SSPL", "EUPL")
UNSAFE_ML_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".bin")


def _as_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def damerau_levenshtein(a: str, b: str) -> int:
    """Compute Damerau-Levenshtein edit distance (handles adjacent transpositions like reqeusts/requests)."""
    len_a, len_b = len(a), len(b)
    if abs(len_a - len_b) > 2:
        return 3
    d = [[0] * (len_b + 1) for _ in range(len_a + 1)]
    for i in range(len_a + 1):
        d[i][0] = i
    for j in range(len_b + 1):
        d[0][j] = j
    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,      # deletion
                d[i][j - 1] + 1,      # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)  # transposition
    return d[len_a][len_b]


def _detect_ecosystem(component: Component) -> str:
    purl = (component.purl or "").lower()
    if purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    meta = component.metadata_ if isinstance(component.metadata_, dict) else {}
    return str(meta.get("ecosystem") or "pypi").lower()


def _check_typosquatting(component: Component) -> dict[str, Any] | None:
    name = (component.name or "").lower().strip()
    if not name or len(name) < 4:
        return None
    # Strip npm scope for comparison
    base_name = name.split("/")[-1]
    eco = _detect_ecosystem(component)
    targets = POPULAR_PACKAGES.get(eco, set()) | POPULAR_PACKAGES["pypi"] | POPULAR_PACKAGES["npm"]
    if base_name in targets:
        return None

    # 1. Edit distance check (1 edit for short names, up to 2 for longer names)
    for target in targets:
        if len(target) < 5:
            continue
        dist = damerau_levenshtein(base_name, target)
        max_dist = 1 if len(target) <= 6 else 2
        if 0 < dist <= max_dist:
            return {
                "threat_type": "typosquatting",
                "severity": "critical" if dist == 1 else "high",
                "confidence_score": 0.92 if dist == 1 else 0.78,
                "summary": f"Potential typosquatting package '{component.name}' closely resembles popular package '{target}' (edit distance {dist}).",
                "evidence": {"target_package": target, "edit_distance": dist, "ecosystem": eco},
            }

    # 2. Combosquatting check (e.g., requests-official, lodash-dev)
    for target in targets:
        if len(target) < 5:
            continue
        for affix in COMBO_AFFIXES:
            if base_name == f"{target}{affix}" or base_name == f"{affix}{target}":
                return {
                    "threat_type": "typosquatting",
                    "severity": "high",
                    "confidence_score": 0.85,
                    "summary": f"Potential combosquatting package '{component.name}' wraps popular package '{target}' with affix '{affix}'.",
                    "evidence": {"target_package": target, "affix": affix, "ecosystem": eco},
                }
    return None


def _check_dependency_confusion(component: Component) -> dict[str, Any] | None:
    name = (component.name or "").lower().strip()
    if any(pat in name for pat in INTERNAL_PATTERNS) and not name.startswith("@"):
        return {
            "threat_type": "dependency-confusion",
            "severity": "high",
            "confidence_score": 0.84,
            "summary": f"Unscoped internal-looking package '{component.name}' is susceptible to public registry dependency confusion.",
            "evidence": {"package_name": component.name, "recommendation": "Use a scoped private namespace and pin private registry resolution."},
        }
    return None


def _check_install_script_and_malware(component: Component) -> dict[str, Any] | None:
    meta = component.metadata_ if isinstance(component.metadata_, dict) else {}
    if meta.get("has_install_script"):
        return {
            "threat_type": "behavioral-risk",
            "severity": "medium",
            "confidence_score": 0.76,
            "summary": f"Package '{component.name}@{component.version}' executes arbitrary install-time lifecycle scripts (hasInstallScript).",
            "evidence": {"has_install_script": True, "ecosystem": meta.get("ecosystem", "npm")},
        }
    return None


def _check_license_risk(component: Component) -> dict[str, Any] | None:
    lic = (component.license or "").upper()
    if not lic:
        return None
    for copyleft in STRONG_COPYLEFT:
        if copyleft in lic and "LGPL" not in lic:
            return {
                "threat_type": "license-risk",
                "severity": "medium",
                "confidence_score": 0.95,
                "summary": f"Component '{component.name}' uses strong copyleft license '{component.license}', posing commercial IP risk.",
                "evidence": {"license": component.license, "category": "strong-copyleft"},
            }
    return None


def _check_ai_model_risk(component: Component) -> dict[str, Any] | None:
    ctype = (component.type or "").lower()
    meta = component.metadata_ if isinstance(component.metadata_, dict) else {}
    weights_format = str(meta.get("weights_format") or component.name or "").lower()
    if ctype in {"machine-learning-model", "ml-model", "ai-model"}:
        if any(ext in weights_format for ext in UNSAFE_ML_EXTENSIONS):
            return {
                "threat_type": "ai-supply-chain",
                "severity": "critical",
                "confidence_score": 0.91,
                "summary": f"AI model '{component.name}' uses unsafe pickle-based weights format, susceptible to arbitrary code execution on load.",
                "evidence": {"weights_format": weights_format, "recommendation": "Convert model weights to safetensors format."},
            }
        if not meta.get("model_card") and not component.license:
            return {
                "threat_type": "ai-supply-chain",
                "severity": "medium",
                "confidence_score": 0.80,
                "summary": f"AI model '{component.name}' lacks model card provenance and license metadata required for EU AI Act Annex IV.",
                "evidence": {"missing": ["model_card", "license"]},
            }
    return None


def serialize_threat(threat: ThreatDetection) -> dict[str, Any]:
    return {
        "id": str(threat.id),
        "sbom_id": str(threat.sbom_id),
        "component_id": str(threat.component_id) if threat.component_id else None,
        "component_name": threat.component_name,
        "threat_type": threat.threat_type,
        "severity": threat.severity,
        "confidence_score": threat.confidence_score,
        "status": threat.status,
        "summary": threat.summary,
        "evidence": threat.evidence,
        "detected_at": (threat.detected_at.isoformat() + "Z") if threat.detected_at else utcnow_iso(),
    }


async def build_threats_for_sbom(
    session: AsyncSession,
    sbom_id: str | UUID,
    threat_types: list[str] | None = None,
) -> list[dict[str, Any]]:
    sbom_uuid = _as_uuid(sbom_id)
    statement = (
        select(Sbom)
        .options(selectinload(Sbom.components))
        .where(Sbom.id == sbom_uuid)
    )
    result = await session.execute(statement)
    sbom = result.scalars().first()
    if not sbom:
        return []

    requested = {item.lower() for item in (threat_types or [])}
    candidate_threats: list[dict[str, Any]] = []

    # Run real component-level supply chain analyzers
    for comp in sbom.components:
        for checker in (
            _check_typosquatting,
            _check_dependency_confusion,
            _check_install_script_and_malware,
            _check_license_risk,
            _check_ai_model_risk,
        ):
            finding = checker(comp)
            if finding and (not requested or finding["threat_type"] in requested):
                finding["component_id"] = comp.id
                finding["component_name"] = comp.name
                candidate_threats.append(finding)

    # SBOM-level supply-chain & transitive exposure posture (preserves backwards compatibility)
    if (not requested or "supply-chain" in requested) and (sbom.risk_score >= 50 or sbom.vulnerability_count > 0):
        candidate_threats.append(
            {
                "component_id": None,
                "component_name": None,
                "threat_type": "supply-chain",
                "severity": "critical" if sbom.risk_score >= 90 else "high" if sbom.risk_score >= 75 else "medium",
                "confidence_score": 0.88 if sbom.risk_score >= 75 else 0.78,
                "summary": f"Dependency chain carries risk score {sbom.risk_score} with {sbom.vulnerability_count} known vulnerability finding(s).",
                "evidence": {"risk_score": sbom.risk_score, "vulnerability_count": sbom.vulnerability_count},
            }
        )

    if (not requested or "dependency" in requested) and (sbom.component_count > 0 or len(sbom.components) > 0):
        transitive_count = sum(
            1 for c in sbom.components if isinstance(c.metadata_, dict) and c.metadata_.get("direct") is False
        )
        if transitive_count > 0 or sbom.component_count >= 2:
            candidate_threats.append(
                {
                    "component_id": None,
                    "component_name": None,
                    "threat_type": "dependency",
                    "severity": "medium",
                    "confidence_score": 0.75,
                    "summary": f"SBOM tracks {max(sbom.component_count, len(sbom.components))} components ({transitive_count} transitive) expanding supply chain attack surface.",
                    "evidence": {"component_count": max(sbom.component_count, len(sbom.components)), "transitive_count": transitive_count},
                }
            )

    # Replace previous open auto-detected threats for this SBOM to avoid duplicates on re-scan
    await session.execute(
        delete(ThreatDetection).where(
            ThreatDetection.sbom_id == sbom_uuid,
            ThreatDetection.status == "open",
        )
    )

    persisted: list[ThreatDetection] = []
    for item in candidate_threats:
        record = ThreatDetection(
            sbom_id=sbom_uuid,
            component_id=item.get("component_id"),
            component_name=item.get("component_name"),
            threat_type=item["threat_type"],
            severity=item["severity"],
            confidence_score=item["confidence_score"],
            status="open",
            summary=item["summary"],
            evidence=item.get("evidence"),
        )
        session.add(record)
        persisted.append(record)

    await session.commit()
    for rec in persisted:
        await session.refresh(rec)

    return [serialize_threat(rec) for rec in persisted]


async def list_threats_for_organization(session: AsyncSession, organization_id: str | UUID) -> list[dict[str, Any]]:
    organization_uuid = _as_uuid(organization_id)
    stmt = (
        select(ThreatDetection)
        .join(Sbom, ThreatDetection.sbom_id == Sbom.id)
        .join(Project, Sbom.project_id == Project.id)
        .where(Project.organization_id == organization_uuid)
        .order_by(ThreatDetection.detected_at.desc())
    )
    result = await session.execute(stmt)
    existing = result.scalars().all()
    if existing:
        return [serialize_threat(t) for t in existing]

    # Fallback: evaluate SBOMs that have not been analyzed yet
    sboms_stmt = select(Sbom).join(Project).where(Project.organization_id == organization_uuid)
    sboms = (await session.execute(sboms_stmt)).scalars().all()
    threats: list[dict[str, Any]] = []
    for sbom in sboms:
        threats.extend(await build_threats_for_sbom(session, sbom.id))
    return threats


async def get_threat_by_id(session: AsyncSession, threat_id: str | UUID, organization_id: str | UUID) -> dict[str, Any] | None:
    threat_uuid = _as_uuid(threat_id)
    org_uuid = _as_uuid(organization_id)
    stmt = (
        select(ThreatDetection)
        .join(Sbom, ThreatDetection.sbom_id == Sbom.id)
        .join(Project, Sbom.project_id == Project.id)
        .where(ThreatDetection.id == threat_uuid, Project.organization_id == org_uuid)
    )
    threat = (await session.execute(stmt)).scalars().first()
    return serialize_threat(threat) if threat else None


async def update_threat_status(
    session: AsyncSession,
    threat_id: str | UUID,
    organization_id: str | UUID,
    new_status: str,
) -> dict[str, Any] | None:
    allowed = {"open", "investigating", "false_positive", "mitigated", "accepted"}
    if new_status not in allowed:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {', '.join(sorted(allowed))}")

    threat_uuid = _as_uuid(threat_id)
    org_uuid = _as_uuid(organization_id)
    stmt = (
        select(ThreatDetection)
        .join(Sbom, ThreatDetection.sbom_id == Sbom.id)
        .join(Project, Sbom.project_id == Project.id)
        .where(ThreatDetection.id == threat_uuid, Project.organization_id == org_uuid)
    )
    threat = (await session.execute(stmt)).scalars().first()
    if not threat:
        return None
    threat.status = new_status
    threat.updated_at = datetime.utcnow()
    await session.commit()
    await session.refresh(threat)
    return serialize_threat(threat)
