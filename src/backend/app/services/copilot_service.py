"""
AI Security Copilot & Deep AI-BOM / Model Artifact Scanner:
- Data-grounded natural-language security assistant querying live SBOMs, CVEs, KEV, EPSS, threats, VEX, and compliance
- Safe static Pickle opcode disassembler (pickletools.genops — NEVER executes pickle.loads)
- HuggingFace / Ollama / ML model provenance & safety scanner
"""
from __future__ import annotations

import base64
import json
import pickletools
import re
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Component,
    ComponentVulnerability,
    Project,
    Sbom,
    ThreatDetection,
    VexStatement,
    Vulnerability,
)
from app.services.compliance_evaluator import evaluate_organization_compliance
from app.utils.time_utils import utcnow_iso

DANGEROUS_PICKLE_GLOBALS = {
    ("os", "system"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "run"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("socket", "create_connection"),
    ("urllib.request", "urlopen"),
}


def _as_uuid(value: str | UUID) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def scan_pickle_bytes_safely(raw_bytes: bytes) -> list[dict[str, Any]]:
    """
    Statically disassemble Python pickle bytecode with pickletools.genops
    to detect arbitrary code execution payloads WITHOUT ever deserializing.
    """
    findings: list[dict[str, Any]] = []
    stack_strings: list[str] = []

    try:
        for opcode, arg, pos in pickletools.genops(raw_bytes):
            op_name = opcode.name
            if op_name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING", "SHORT_BINSTRING"} and isinstance(arg, str):
                stack_strings.append(arg)
            elif op_name == "GLOBAL" and isinstance(arg, str):
                parts = arg.split(" ", 1)
                mod, attr = (parts[0], parts[1]) if len(parts) == 2 else (arg, "")
                if (mod, attr) in DANGEROUS_PICKLE_GLOBALS or mod in {"os", "posix", "subprocess"}:
                    findings.append(
                        {
                            "rule_id": "AIBOM-PICKLE-RCE",
                            "severity": "critical",
                            "position": pos,
                            "symbol": f"{mod}.{attr}",
                            "summary": f"Malicious pickle GLOBAL reference '{mod}.{attr}' executes arbitrary code on model load.",
                        }
                    )
            elif op_name == "STACK_GLOBAL" and len(stack_strings) >= 2:
                mod, attr = stack_strings[-2], stack_strings[-1]
                if (mod, attr) in DANGEROUS_PICKLE_GLOBALS or mod in {"os", "posix", "subprocess"}:
                    findings.append(
                        {
                            "rule_id": "AIBOM-PICKLE-RCE",
                            "severity": "critical",
                            "position": pos,
                            "symbol": f"{mod}.{attr}",
                            "summary": f"Malicious pickle STACK_GLOBAL reference '{mod}.{attr}' executes arbitrary code on model load.",
                        }
                    )
    except Exception:
        # Fallback regex inspection on raw bytes if truncated/non-standard pickle
        text = raw_bytes.decode("latin-1", errors="ignore")
        for mod, attr in DANGEROUS_PICKLE_GLOBALS:
            if mod in text and attr in text:
                findings.append(
                    {
                        "rule_id": "AIBOM-PICKLE-PATTERN",
                        "severity": "critical",
                        "position": 0,
                        "symbol": f"{mod}.{attr}",
                        "summary": f"Suspicious serialized reference to '{mod}.{attr}' detected in model binary.",
                    }
                )
    return findings


def scan_ai_bom_artifact(
    filename: str,
    content_text: str | None = None,
    content_base64: str | None = None,
) -> dict[str, Any]:
    """Scan an AI/ML artifact (pickle weights, HuggingFace config.json, Modelfile, or Python ML script)."""
    fname = filename.lower().strip()
    findings: list[dict[str, Any]] = []
    detected_models: list[dict[str, Any]] = []

    if content_base64:
        raw_bytes = base64.b64decode(content_base64)
        findings.extend(scan_pickle_bytes_safely(raw_bytes))
        detected_models.append({"name": filename, "format": "pickle-binary", "safe_serialization": len(findings) == 0})

    if content_text:
        # 1. Check HuggingFace config.json or model card JSON
        if fname.endswith(".json") or content_text.lstrip().startswith("{"):
            try:
                cfg = json.loads(content_text)
                if isinstance(cfg, dict):
                    model_type = cfg.get("model_type") or cfg.get("_name_or_path")
                    if model_type:
                        detected_models.append(
                            {
                                "name": str(model_type),
                                "architectures": cfg.get("architectures") or [],
                                "transformers_version": cfg.get("transformers_version"),
                            }
                        )
                    if cfg.get("auto_map"):
                        findings.append(
                            {
                                "rule_id": "AIBOM-TRUST-REMOTE-CODE",
                                "severity": "high",
                                "summary": "Model config defines 'auto_map' custom code execution (requires trust_remote_code=True).",
                            }
                        )
            except json.JSONDecodeError:
                pass

        # 2. Check Ollama Modelfile
        from_matches = re.findall(r"^\s*FROM\s+([^\s]+)", content_text, re.IGNORECASE | re.MULTILINE)
        for m in from_matches:
            detected_models.append({"name": m, "format": "ollama-modelfile"})

        # 3. Check Python ML loading scripts for unsafe loading patterns
        if "trust_remote_code=True" in content_text or "trust_remote_code = True" in content_text:
            findings.append(
                {
                    "rule_id": "AIBOM-REMOTE-CODE",
                    "severity": "high",
                    "summary": "Unsafe 'trust_remote_code=True' allows arbitrary remote Python execution when loading HuggingFace models.",
                }
            )
        if re.search(r"torch\.load\s*\([^)]*\)", content_text) and "weights_only=True" not in content_text:
            findings.append(
                {
                    "rule_id": "AIBOM-UNSAFE-TORCH-LOAD",
                    "severity": "critical",
                    "summary": "torch.load() called without weights_only=True; vulnerable to pickle arbitrary code execution.",
                }
            )

    risk_level = (
        "critical" if any(f["severity"] == "critical" for f in findings)
        else "high" if any(f["severity"] == "high" for f in findings)
        else "low"
    )
    return {
        "filename": filename,
        "risk_level": risk_level,
        "findings_count": len(findings),
        "findings": findings,
        "detected_models": detected_models,
        "scanned_at": utcnow_iso(),
    }


async def query_security_copilot(
    session: AsyncSession,
    organization_id: str | UUID,
    question: str,
) -> dict[str, Any]:
    """
    Data-grounded AI Security Copilot answering natural-language questions
    using live organization SBOMs, vulnerabilities (KEV/EPSS), threats, VEX, and compliance.
    """
    org_uuid = _as_uuid(organization_id)
    q = (question or "").lower().strip()

    sboms = (
        await session.execute(
            select(Sbom)
            .options(selectinload(Sbom.components))
            .join(Project)
            .where(Project.organization_id == org_uuid)
        )
    ).scalars().all()
    sbom_ids = [s.id for s in sboms]

    vulns: list[tuple[Component, Vulnerability]] = []
    threats: list[ThreatDetection] = []
    vex_list: list[VexStatement] = []

    if sbom_ids:
        vulns = (
            await session.execute(
                select(Component, Vulnerability)
                .join(ComponentVulnerability, ComponentVulnerability.component_id == Component.id)
                .join(Vulnerability, ComponentVulnerability.vulnerability_id == Vulnerability.id)
                .where(Component.sbom_id.in_(sbom_ids))
            )
        ).all()
        threats = (
            await session.execute(
                select(ThreatDetection).where(
                    ThreatDetection.sbom_id.in_(sbom_ids),
                    ThreatDetection.status == "open",
                )
            )
        ).scalars().all()
        vex_list = (
            await session.execute(
                select(VexStatement).where(VexStatement.organization_id == org_uuid)
            )
        ).scalars().all()

    compliance = await evaluate_organization_compliance(session, org_uuid)

    kev_hits = [(c, v) for c, v in vulns if bool((v.metadata_ or {}).get("in_kev", False))]
    crit_hits = [(c, v) for c, v in vulns if (v.severity or "").lower() == "critical"]
    total_components = sum(len(s.components) for s in sboms)

    # Intent routing for precise, grounded answers
    actions: list[str] = []
    if any(k in q for k in ("kev", "exploit", "critical", "blast", "urgent", "log4j")):
        intent = "kev_and_critical_exposure"
        if kev_hits or crit_hits:
            lines = [f"Found **{len(kev_hits)} CISA KEV** and **{len(crit_hits)} Critical** vulnerability finding(s) across {len(sboms)} SBOM(s):"]
            for comp, v in (kev_hits or crit_hits)[:8]:
                fix = (v.metadata_ or {}).get("fixed_version")
                epss = (v.metadata_ or {}).get("epss_score")
                lines.append(
                    f"- `{comp.name}@{comp.version}` → **{v.cve_id}** (CVSS {v.cvss_v3_score}, EPSS {epss or 'N/A'}, KEV={'YES' if (v.metadata_ or {}).get('in_kev') else 'no'})"
                    + (f" — **Fix: upgrade to `{fix}`**" if fix else "")
                )
            answer = "\n".join(lines)
            actions = ["Generate Auto-Fix patches via GET /api/v1/sboms/{id}/autofix", "Run AST Reachability to verify exploit path"]
        else:
            answer = f"Good news: **0 CISA KEV** and **0 Critical** vulnerabilities are currently active across your {len(sboms)} SBOM(s) ({total_components} components)."
    elif any(k in q for k in ("compliance", "cra", "cisa", "fda", "ai act", "audit", "executive", "summary")):
        intent = "compliance_and_executive_summary"
        fw_lines = [f"- **{f['name']}**: {f['score']}% (Grade {f['grade']})" for f in compliance["frameworks"]]
        answer = (
            f"### Executive Security & Compliance Summary\n"
            f"- **Overall Compliance Score:** {compliance['overall_compliance_score']}% (Grade **{compliance['overall_grade']}**)\n"
            f"- **Inventory:** {len(sboms)} SBOM(s), {total_components} component(s), {len(vex_list)} VEX attestation(s)\n"
            f"- **Exposure:** {len(vulns)} vulnerability finding(s) ({len(kev_hits)} CISA KEV), {len(threats)} open supply-chain threat(s)\n\n"
            f"**Framework Readiness:**\n" + "\n".join(fw_lines)
        )
        actions = ["Export signed Audit Evidence Bundle via GET /api/v1/sboms/{id}/audit-bundle"]
    elif any(k in q for k in ("threat", "typosquat", "malware", "confusion", "license", "gpl", "ai-bom", "model", "pickle")):
        intent = "supply_chain_threats"
        if threats:
            lines = [f"Detected **{len(threats)} open supply-chain threat(s)**:"]
            for t in threats[:8]:
                lines.append(f"- **[{t.severity.upper()}] {t.threat_type}** on `{t.component_name or 'SBOM'}`: {t.summary}")
            answer = "\n".join(lines)
            actions = ["Triage threats in the Threat Detection console", "Block typosquatting in CI with --fail-on typosquat"]
        else:
            answer = f"No open supply-chain threats (typosquatting, dependency confusion, copyleft, or AI-BOM risks) across {total_components} components."
    else:
        intent = "general_posture"
        answer = (
            f"SecureChain currently monitors **{len(sboms)} SBOM(s)** covering **{total_components} component(s)**: "
            f"**{len(vulns)} vulnerability finding(s)** ({len(kev_hits)} CISA KEV), **{len(threats)} open supply-chain threat(s)**, "
            f"and **{compliance['overall_compliance_score']}%** overall regulatory compliance (Grade {compliance['overall_grade']}). "
            f"Ask me about *CISA KEV exposure*, *EU CRA / FDA compliance*, *typosquatting threats*, or *remediation steps*."
        )
        actions = ["Ask: 'Which packages have CISA KEV vulnerabilities?'", "Ask: 'Draft an executive compliance summary'"]

    return {
        "question": question,
        "intent": intent,
        "answer": answer,
        "recommended_actions": actions,
        "context_metrics": {
            "sboms": len(sboms),
            "components": total_components,
            "vulnerabilities": len(vulns),
            "kev_count": len(kev_hits),
            "open_threats": len(threats),
            "compliance_score": compliance["overall_compliance_score"],
        },
        "generated_at": utcnow_iso(),
    }
