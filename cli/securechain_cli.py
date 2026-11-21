#!/usr/bin/env python3
"""
securechain-cli — Standalone DevSecOps & CI/CD Supply Chain Security Scanner.

Features:
- Auto-discovers lockfiles (package-lock.json, package.json, requirements.txt, go.mod, Dockerfile)
- Generates CycloneDX 1.5 SBOM
- Runs version-range vulnerability matching (OSV/KEV/EPSS), typosquatting/dependency-confusion checks,
  and Python/JS/TS AST reachability analysis
- Exports SARIF 2.1.0 (for GitHub Code Scanning), CycloneDX JSON, and Markdown PR comments
- Supports Policy-as-Code CI gates (--fail-on critical|high|kev|typosquat)
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

# Allow running directly from repo root without installing package
_REPO_ROOT = Path(__file__).resolve().parent.parent
_BACKEND_DIR = _REPO_ROOT / "src" / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.services.intel_service import match_local_intel  # noqa: E402
from app.services.reachability_service import evaluate_reachability  # noqa: E402
from app.services.sbom_parser import export_cyclonedx, parse_sbom_input  # noqa: E402
from app.services.threat_service import (  # noqa: E402
    _check_ai_model_risk,
    _check_dependency_confusion,
    _check_install_script_and_malware,
    _check_license_risk,
    _check_typosquatting,
)

LOCKFILE_NAMES = {
    "package-lock.json": "package-lock.json",
    "package.json": "package.json",
    "requirements.txt": "requirements.txt",
    "go.mod": "go.mod",
    "Dockerfile": "dockerfile",
}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".pytest_cache"}
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx"}


def discover_and_scan(target_dir: Path) -> dict[str, Any]:
    """Scan a directory for lockfiles and source files, returning full SBOM, vulns, threats, and reachability."""
    components: list[SimpleNamespace] = []
    source_files: dict[str, str] = {}
    scanned_manifests: list[str] = []

    for path in target_dir.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        rel = str(path.relative_to(target_dir)).replace("\\", "/")
        if path.name in LOCKFILE_NAMES:
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
                _, parsed = parse_sbom_input(LOCKFILE_NAMES[path.name], raw)
                scanned_manifests.append(rel)
                for item in parsed:
                    components.append(
                        SimpleNamespace(
                            name=item["name"],
                            version=item.get("version") or "0.0.0",
                            type=item.get("type") or "library",
                            purl=item.get("purl"),
                            license=item.get("license"),
                            author=item.get("author"),
                            metadata_=item.get("metadata") or {},
                        )
                    )
            except Exception:
                continue
        elif path.suffix.lower() in SOURCE_EXTS and path.stat().st_size <= 250_000:
            try:
                source_files[rel] = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

    # Deduplicate components by (name, version)
    dedup: dict[tuple[str, str], SimpleNamespace] = {}
    for c in components:
        dedup[(c.name.lower(), c.version)] = c
    unique_components = list(dedup.values())

    # Vulnerability matching
    vuln_findings: list[dict[str, Any]] = []
    for comp in unique_components:
        for match in match_local_intel(comp):
            vuln_findings.append(
                {
                    "component_name": comp.name,
                    "component_version": comp.version,
                    "component_purl": comp.purl,
                    **match,
                }
            )

    # Supply-chain threat detection
    threats: list[dict[str, Any]] = []
    for comp in unique_components:
        for checker in (
            _check_typosquatting,
            _check_dependency_confusion,
            _check_install_script_and_malware,
            _check_license_risk,
            _check_ai_model_risk,
        ):
            hit = checker(comp)
            if hit:
                hit["component_name"] = comp.name
                hit["component_version"] = comp.version
                threats.append(hit)

    # AST Reachability analysis
    reachability = evaluate_reachability(source_files, vuln_findings)
    reach_map = {(r["component_name"], r["cve_id"]): r["reachability"] for r in reachability["results"]}
    for v in vuln_findings:
        v["reachability"] = reach_map.get((v["component_name"], v["cve_id"]), "unknown")

    sbom_stub = SimpleNamespace(id="local-cli-scan", version="1.0")
    cyclonedx_doc = export_cyclonedx(sbom_stub, unique_components, project_name=target_dir.name)

    return {
        "target": str(target_dir),
        "manifests_scanned": scanned_manifests,
        "component_count": len(unique_components),
        "vulnerabilities": vuln_findings,
        "threats": threats,
        "reachability": reachability,
        "cyclonedx": cyclonedx_doc,
    }


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert scan findings into SARIF 2.1.0 format for GitHub Code Scanning."""
    results = []
    for v in report["vulnerabilities"]:
        level = "error" if v["severity"] in {"critical", "high"} or v.get("in_kev") else "warning"
        results.append(
            {
                "ruleId": v["cve_id"],
                "level": level,
                "message": {
                    "text": f"{v['component_name']}@{v['component_version']} ({v['severity'].upper()}, reachability={v.get('reachability')}): {v['description']} Fix: {v.get('recommendation')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report["manifests_scanned"][0] if report["manifests_scanned"] else "SBOM"}
                        }
                    }
                ],
            }
        )
    for t in report["threats"]:
        level = "error" if t["severity"] in {"critical", "high"} else "warning"
        results.append(
            {
                "ruleId": f"SC-{t['threat_type'].upper()}",
                "level": level,
                "message": {"text": t["summary"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report["manifests_scanned"][0] if report["manifests_scanned"] else "SBOM"}
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureChain CLI",
                        "version": "1.1.0",
                        "informationUri": "https://github.com/securechain",
                    }
                },
                "results": results,
            }
        ],
    }


def to_markdown_pr_comment(report: dict[str, Any]) -> str:
    """Render a clean Markdown summary for GitHub/GitLab Pull Request comments."""
    vulns = report["vulnerabilities"]
    threats = report["threats"]
    kev_count = sum(1 for v in vulns if v.get("in_kev"))
    reach = report["reachability"]

    lines = [
        "## SecureChain Supply Chain Security Gate",
        "",
        f"- **Manifests scanned:** {len(report['manifests_scanned'])} ({', '.join(report['manifests_scanned']) or 'none'})",
        f"- **Components discovered:** {report['component_count']}",
        f"- **Vulnerabilities:** {len(vulns)} (**{kev_count} CISA KEV**, {reach['reachable_count']} reachable / {reach['unreachable_count']} unreachable)",
        f"- **Supply-Chain Threats:** {len(threats)}",
        "",
    ]
    if vulns:
        lines.append("### Vulnerabilities")
        lines.append("| Package | Version | CVE | Severity | KEV | Reachability | Fix |")
        lines.append("| :--- | :--- | :--- | :--- | :---: | :--- | :--- |")
        for v in vulns:
            lines.append(
                f"| `{v['component_name']}` | `{v['component_version']}` | {v['cve_id']} | **{v['severity'].upper()}** | {'YES' if v.get('in_kev') else 'no'} | {v.get('reachability')} | {v.get('fixed_version') or 'See advisory'} |"
            )
        lines.append("")
    if threats:
        lines.append("### Supply-Chain Threats")
        lines.append("| Type | Component | Severity | Summary |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for t in threats:
            lines.append(f"| `{t['threat_type']}` | `{t.get('component_name')}` | **{t['severity'].upper()}** | {t['summary']} |")
        lines.append("")
    if not vulns and not threats:
        lines.append("No vulnerabilities or supply-chain threats detected.")
    return "\n".join(lines)


def evaluate_policy_gate(report: dict[str, Any], fail_on: str | None) -> tuple[bool, str]:
    """Return (passed, reason) according to CI policy gate."""
    if not fail_on or fail_on == "none":
        return True, "Policy gate disabled."
    mode = fail_on.lower()
    vulns = report["vulnerabilities"]
    threats = report["threats"]

    if mode == "kev" and any(v.get("in_kev") for v in vulns):
        return False, "Blocked: CISA KEV vulnerability detected."
    if mode == "critical" and (
        any(v["severity"] == "critical" for v in vulns) or any(t["severity"] == "critical" for t in threats)
    ):
        return False, "Blocked: Critical vulnerability or threat detected."
    if mode == "high" and (
        any(v["severity"] in {"critical", "high"} for v in vulns)
        or any(t["severity"] in {"critical", "high"} for t in threats)
    ):
        return False, "Blocked: High or Critical vulnerability/threat detected."
    if mode == "typosquat" and any(t["threat_type"] == "typosquatting" for t in threats):
        return False, "Blocked: Potential typosquatting package detected."
    return True, f"Policy gate passed (--fail-on {mode})."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securechain", description="SecureChain Supply Chain & SBOM CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a directory for SBOMs, CVEs, threats, and AST reachability")
    scan_p.add_argument("path", nargs="?", default=".", help="Target repository directory")
    scan_p.add_argument("--fail-on", choices=["none", "kev", "critical", "high", "typosquat"], default="kev")
    scan_p.add_argument("--cyclonedx", help="Write CycloneDX 1.5 SBOM JSON to path")
    scan_p.add_argument("--sarif", help="Write SARIF 2.1.0 report to path")
    scan_p.add_argument("--markdown", help="Write Markdown PR comment to path")
    scan_p.add_argument("--api-url", help="Upload CycloneDX SBOM to SecureChain API (e.g. http://localhost:8000)")
    scan_p.add_argument("--api-key", help="Scoped X-API-Key (sc_live_...) for remote upload")
    scan_p.add_argument("--project-id", help="Target project UUID when uploading to SecureChain API")
    scan_p.add_argument("--json", action="store_true", dest="as_json", help="Print full JSON report to stdout")

    args = parser.parse_args(argv)
    if args.command == "scan":
        target = Path(args.path).resolve()
        report = discover_and_scan(target)

        if args.cyclonedx:
            Path(args.cyclonedx).write_text(json.dumps(report["cyclonedx"], indent=2), encoding="utf-8")
        if args.sarif:
            Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
        if args.markdown:
            Path(args.markdown).write_text(to_markdown_pr_comment(report), encoding="utf-8")

        upload_status = None
        if args.api_url and args.api_key and args.project_id:
            endpoint = args.api_url.rstrip("/") + "/api/v1/sboms/upload"
            req_body = json.dumps(
                {
                    "project_id": args.project_id,
                    "source_type": "cyclonedx-json",
                    "content": report["cyclonedx"],
                    "version": "cli-scan",
                    "auto_scan": True,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=req_body,
                headers={"Content-Type": "application/json", "X-API-Key": args.api_key},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    upload_status = {"uploaded": True, "http_status": resp.status}
            except Exception as exc:
                upload_status = {"uploaded": False, "error": str(exc)}

        passed, reason = evaluate_policy_gate(report, args.fail_on)
        if args.as_json:
            print(json.dumps({**report, "remote_upload": upload_status, "policy_gate": {"passed": passed, "reason": reason}}, indent=2))
        else:
            print(to_markdown_pr_comment(report))
            if upload_status:
                print(f"\nRemote Sync: {upload_status}")
            print(f"\nGate Result: {'PASS' if passed else 'FAIL'} — {reason}")
        return 0 if passed else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
