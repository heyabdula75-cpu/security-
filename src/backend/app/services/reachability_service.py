"""
Static AST Reachability Analyzer for Python and JavaScript/TypeScript.
Traces imports and call expressions to determine whether vulnerable SBOM components
are actually imported and invoked in application source code — reducing CVE alert fatigue.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

# Map known CVEs to specific vulnerable symbols/functions when deeper symbol-level matching is possible
CVE_VULNERABLE_SYMBOLS: dict[str, set[str]] = {
    "CVE-2019-10744": {"defaultsDeep", "merge", "mergeWith"},
    "CVE-2023-32681": {"get", "post", "put", "delete", "request", "Session"},
    "CVE-2022-31129": {"moment", "locale"},
    "CVE-2024-3651": {"encode"},
    "CVE-2021-44228": {"getLogger", "info", "error", "warn"},
}

# Normalize PyPI / npm package names to common Python/JS import module names
PACKAGE_IMPORT_ALIASES: dict[str, set[str]] = {
    "python-requests": {"requests"},
    "pillow": {"PIL"},
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "scikit-learn": {"sklearn"},
    "lodash": {"lodash", "_"},
    "moment": {"moment"},
}

JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:(?P<default>[A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{?(?P<named>[^}]*)\}?\s*from\s*)?['"](?P<mod1>[^'"]+)['"]|require\(\s*['"](?P<mod2>[^'"]+)['"]\s*\))"""
)
JS_CALL_RE = re.compile(r"""\b([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?\s*\(""")


def analyze_python_source(filename: str, source: str) -> dict[str, Any]:
    """Parse Python source with stdlib AST to extract imported modules and called symbols."""
    imports: dict[str, list[dict[str, Any]]] = {}
    calls: list[dict[str, Any]] = []
    alias_to_module: dict[str, str] = {}

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return {"imports": {}, "calls": []}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0].lower()
                local_name = (alias.asname or root_mod).lower()
                alias_to_module[local_name] = root_mod
                imports.setdefault(root_mod, []).append({"file": filename, "line": node.lineno, "imported": alias.name})
        elif isinstance(node, ast.ImportFrom) and node.module:
            root_mod = node.module.split(".")[0].lower()
            for alias in node.names:
                local_name = (alias.asname or alias.name).lower()
                alias_to_module[local_name] = root_mod
                imports.setdefault(root_mod, []).append(
                    {"file": filename, "line": node.lineno, "imported": f"{node.module}.{alias.name}"}
                )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                owner = node.func.value.id.lower() if isinstance(node.func.value, ast.Name) else None
                calls.append(
                    {
                        "file": filename,
                        "line": node.lineno,
                        "owner": alias_to_module.get(owner, owner) if owner else None,
                        "symbol": attr,
                    }
                )
            elif isinstance(node.func, ast.Name):
                fn_name = node.func.id
                calls.append(
                    {
                        "file": filename,
                        "line": node.lineno,
                        "owner": alias_to_module.get(fn_name.lower()),
                        "symbol": fn_name,
                    }
                )

    return {"imports": imports, "calls": calls}


def analyze_js_ts_source(filename: str, source: str) -> dict[str, Any]:
    """Extract ES/CommonJS imports and function calls from JS/TS source."""
    imports: dict[str, list[dict[str, Any]]] = {}
    calls: list[dict[str, Any]] = []

    for lineno, line in enumerate(source.splitlines(), start=1):
        for match in JS_IMPORT_RE.finditer(line):
            mod = (match.group("mod1") or match.group("mod2") or "").strip()
            if not mod or mod.startswith("."):
                continue
            root_mod = mod.split("/")[0].lower() if not mod.startswith("@") else "/".join(mod.split("/")[:2]).lower()
            imports.setdefault(root_mod, []).append({"file": filename, "line": lineno, "imported": mod})
        for call_match in JS_CALL_RE.finditer(line):
            obj, prop = call_match.group(1), call_match.group(2)
            calls.append(
                {
                    "file": filename,
                    "line": lineno,
                    "owner": obj.lower() if prop else None,
                    "symbol": prop or obj,
                }
            )

    return {"imports": imports, "calls": calls}


def analyze_source_files(files: dict[str, str]) -> dict[str, Any]:
    """Analyze a map of {filepath: source_code} across Python and JS/TS."""
    all_imports: dict[str, list[dict[str, Any]]] = {}
    all_calls: list[dict[str, Any]] = []

    for filepath, content in files.items():
        ext = Path(filepath).suffix.lower()
        if ext == ".py":
            res = analyze_python_source(filepath, content)
        elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            res = analyze_js_ts_source(filepath, content)
        else:
            continue

        for mod, locs in res["imports"].items():
            all_imports.setdefault(mod, []).extend(locs)
        all_calls.extend(res["calls"])

    return {"imports": all_imports, "calls": all_calls, "files_analyzed": len(files)}


def evaluate_reachability(
    files: dict[str, str],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Evaluate reachability for a list of vulnerability findings:
    Each finding dict should have: component_name, cve_id, (optional) component_purl.
    """
    graph = analyze_source_files(files)
    imports_map: dict[str, list[dict[str, Any]]] = graph["imports"]
    calls_list: list[dict[str, Any]] = graph["calls"]

    results: list[dict[str, Any]] = []
    reachable_count = 0
    unreachable_count = 0

    for item in findings:
        pkg = (item.get("component_name") or "").lower().strip()
        cve_id = (item.get("cve_id") or "").upper().strip()
        candidate_modules = {pkg, pkg.replace("-", "_")} | {a.lower() for a in PACKAGE_IMPORT_ALIASES.get(pkg, set())}

        import_hits: list[dict[str, Any]] = []
        for mod in candidate_modules:
            if mod in imports_map:
                import_hits.extend(imports_map[mod])

        target_symbols = CVE_VULNERABLE_SYMBOLS.get(cve_id, set())
        symbol_hits = [
            c for c in calls_list
            if (c["symbol"] in target_symbols) and (not c["owner"] or c["owner"] in candidate_modules or c["owner"] in {"_"})
        ]

        if import_hits and (not target_symbols or symbol_hits):
            status = "reachable"
            reachable_count += 1
            reason = (
                f"Vulnerable symbol(s) invoked in {symbol_hits[0]['file']}:{symbol_hits[0]['line']}"
                if symbol_hits
                else f"Package '{pkg}' is imported in {import_hits[0]['file']}:{import_hits[0]['line']}"
            )
        elif import_hits and target_symbols and not symbol_hits:
            status = "unreachable"
            unreachable_count += 1
            reason = f"Package '{pkg}' is imported, but vulnerable function(s) {sorted(target_symbols)} are never invoked."
        else:
            status = "unreachable"
            unreachable_count += 1
            reason = f"Package '{pkg}' is not imported in any analyzed source file."

        results.append(
            {
                "component_name": item.get("component_name"),
                "component_purl": item.get("component_purl"),
                "cve_id": cve_id,
                "reachability": status,
                "reason": reason,
                "import_locations": import_hits[:5],
                "symbol_locations": symbol_hits[:5],
                "recommended_vex_status": "affected" if status == "reachable" else "not_affected",
                "recommended_vex_justification": None if status == "reachable" else "vulnerable_code_not_in_execute_path",
            }
        )

    total = len(results)
    noise_reduction = round((unreachable_count / total) * 100, 1) if total else 0.0
    return {
        "files_analyzed": graph["files_analyzed"],
        "total_findings": total,
        "reachable_count": reachable_count,
        "unreachable_count": unreachable_count,
        "noise_reduction_percent": noise_reduction,
        "results": results,
    }
