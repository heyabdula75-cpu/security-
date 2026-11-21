"""
Automated SBOM & Lockfile Parser, CycloneDX/SPDX Exporter, SBOM Diff, and CISA Completeness Evaluator.

Supports:
- CycloneDX JSON (1.4 / 1.5 / 1.6, including ML-BOM / AI-BOM component types)
- SPDX JSON (2.2 / 2.3)
- npm package-lock.json (v1, v2, v3) and package.json
- Python requirements.txt and pyproject.toml
- Go go.mod
- Dockerfile (FROM base images)
"""
from __future__ import annotations

import json
import re
from typing import Any
from uuid import uuid4

from app.utils.time_utils import utcnow_iso


def _build_purl(ecosystem: str, name: str, version: str | None) -> str:
    clean_name = name.strip()
    if ecosystem == "npm" and clean_name.startswith("@") and "/" in clean_name:
        scope, pkg = clean_name.split("/", 1)
        clean_name = f"{scope.replace('@', '%40')}/{pkg}"
    ver_suffix = f"@{version.strip()}" if version else ""
    return f"pkg:{ecosystem}/{clean_name}{ver_suffix}"


def _extract_cyclonedx_license(comp: dict[str, Any]) -> str | None:
    licenses = comp.get("licenses") or []
    found: list[str] = []
    for entry in licenses:
        if isinstance(entry, dict):
            lic = entry.get("license") or {}
            lic_id = lic.get("id") or lic.get("name") or entry.get("expression")
            if lic_id:
                found.append(str(lic_id))
        elif isinstance(entry, str):
            found.append(entry)
    return ", ".join(found) if found else None


def parse_cyclonedx_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for comp in payload.get("components") or []:
        name = comp.get("name")
        if not name:
            continue
        version = comp.get("version") or "0.0.0"
        comp_type = comp.get("type") or "library"
        purl = comp.get("purl")
        hashes = {h.get("alg", "SHA-256"): h.get("content") for h in (comp.get("hashes") or []) if h.get("content")}
        metadata: dict[str, Any] = {
            "bom_ref": comp.get("bom-ref"),
            "hashes": hashes,
            "scope": comp.get("scope", "required"),
        }
        if comp.get("modelCard"):
            metadata["model_card"] = comp["modelCard"]
        if comp.get("externalReferences"):
            metadata["external_references"] = comp["externalReferences"]
        components.append(
            {
                "name": str(name),
                "version": str(version),
                "type": str(comp_type),
                "purl": purl,
                "license": _extract_cyclonedx_license(comp),
                "author": comp.get("author") or (comp.get("supplier") or {}).get("name"),
                "metadata": metadata,
            }
        )
    return components


def parse_spdx_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for pkg in payload.get("packages") or []:
        name = pkg.get("name")
        if not name:
            continue
        version = pkg.get("versionInfo") or "0.0.0"
        purl = None
        for ref in pkg.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        if lic in {"NOASSERTION", "NONE"}:
            lic = None
        hashes = {c.get("algorithm", "SHA256"): c.get("checksumValue") for c in (pkg.get("checksums") or []) if c.get("checksumValue")}
        components.append(
            {
                "name": str(name),
                "version": str(version),
                "type": str(pkg.get("primaryPackagePurpose") or "library").lower(),
                "purl": purl,
                "license": lic,
                "author": pkg.get("supplier") or pkg.get("originator"),
                "metadata": {"spdx_id": pkg.get("SPDXID"), "hashes": hashes},
            }
        )
    return components


def parse_package_lock_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    # lockfileVersion 2 & 3 use "packages"
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path_key, info in packages.items():
            if not path_key or not isinstance(info, dict):
                continue
            # Extract package name from node_modules/... path
            if "node_modules/" in path_key:
                name = path_key.split("node_modules/")[-1]
            else:
                name = info.get("name") or path_key
            version = info.get("version")
            if not name or not version:
                continue
            key = (name, str(version))
            if key in seen:
                continue
            seen.add(key)
            depth = path_key.count("node_modules/")
            components.append(
                {
                    "name": name,
                    "version": str(version),
                    "type": "library",
                    "purl": _build_purl("npm", name, str(version)),
                    "license": info.get("license"),
                    "author": None,
                    "metadata": {
                        "ecosystem": "npm",
                        "direct": depth == 1,
                        "dev": bool(info.get("dev", False)),
                        "integrity": info.get("integrity"),
                        "hashes": {"SHA-512": info["integrity"]} if info.get("integrity") else {},
                        "has_install_script": bool(info.get("hasInstallScript", False)),
                    },
                }
            )
        return components

    # lockfileVersion 1 uses recursive "dependencies"
    def _walk_v1(deps: dict[str, Any], is_direct: bool) -> None:
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if version:
                key = (name, str(version))
                if key not in seen:
                    seen.add(key)
                    components.append(
                        {
                            "name": name,
                            "version": str(version),
                            "type": "library",
                            "purl": _build_purl("npm", name, str(version)),
                            "license": None,
                            "author": None,
                            "metadata": {
                                "ecosystem": "npm",
                                "direct": is_direct,
                                "dev": bool(info.get("dev", False)),
                                "integrity": info.get("integrity"),
                                "hashes": {"SHA-512": info["integrity"]} if info.get("integrity") else {},
                            },
                        }
                    )
            if isinstance(info.get("dependencies"), dict):
                _walk_v1(info["dependencies"], False)

    if isinstance(payload.get("dependencies"), dict):
        _walk_v1(payload["dependencies"], True)
    return components


def parse_package_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for section, is_dev in (("dependencies", False), ("devDependencies", True)):
        deps = payload.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, raw_ver in deps.items():
            clean_ver = re.sub(r"^[\^~>=<=\s]+", "", str(raw_ver)).strip() or "0.0.0"
            components.append(
                {
                    "name": name,
                    "version": clean_ver,
                    "type": "library",
                    "purl": _build_purl("npm", name, clean_ver),
                    "license": None,
                    "author": None,
                    "metadata": {"ecosystem": "npm", "direct": True, "dev": is_dev, "version_spec": str(raw_ver)},
                }
            )
    return components


def parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    line_re = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([^\s;#]+))?")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = line_re.match(line)
        if not match:
            continue
        name, op, version = match.group(1), match.group(2), match.group(3)
        clean_ver = (version or "0.0.0").rstrip(",")
        components.append(
            {
                "name": name,
                "version": clean_ver,
                "type": "library",
                "purl": _build_purl("pypi", name.lower(), clean_ver),
                "license": None,
                "author": None,
                "metadata": {"ecosystem": "pypi", "direct": True, "operator": op or "unpinned"},
            }
        )
    return components


def parse_go_mod(content: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    in_block = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = None
        if line.startswith("require ") and "(" not in line:
            target = line[len("require "):].strip()
        elif in_block:
            target = line
        if not target:
            continue
        is_indirect = "// indirect" in target
        clean = target.split("//")[0].strip()
        parts = clean.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1].lstrip("v")
            components.append(
                {
                    "name": name,
                    "version": version,
                    "type": "library",
                    "purl": _build_purl("golang", name, f"v{version}"),
                    "license": None,
                    "author": None,
                    "metadata": {"ecosystem": "golang", "direct": not is_indirect},
                }
            )
    return components


def parse_dockerfile(content: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    from_re = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", re.IGNORECASE)
    for raw_line in content.splitlines():
        match = from_re.match(raw_line)
        if not match:
            continue
        image_ref = match.group(1)
        if image_ref.lower() == "scratch":
            continue
        if ":" in image_ref:
            name, tag = image_ref.rsplit(":", 1)
        else:
            name, tag = image_ref, "latest"
        components.append(
            {
                "name": name,
                "version": tag,
                "type": "container",
                "purl": _build_purl("oci", name, tag),
                "license": None,
                "author": None,
                "metadata": {"ecosystem": "oci", "direct": True, "source_file": "Dockerfile"},
            }
        )
    return components


def parse_sbom_input(source_type: str, raw_content: str | dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """
    Auto-detect or explicitly parse an SBOM/lockfile payload into normalized component dicts.
    Returns (detected_format, components).
    """
    stype = (source_type or "auto").lower().strip()

    if isinstance(raw_content, dict):
        if stype in {"cyclonedx", "cyclonedx-json"} or raw_content.get("bomFormat") == "CycloneDX":
            return "cyclonedx-json", parse_cyclonedx_json(raw_content)
        if stype in {"spdx", "spdx-json"} or "spdxVersion" in raw_content:
            return "spdx-json", parse_spdx_json(raw_content)
        if stype == "package-lock.json" or "lockfileVersion" in raw_content:
            return "package-lock.json", parse_package_lock_json(raw_content)
        if stype == "package.json" or "dependencies" in raw_content or "devDependencies" in raw_content:
            return "package.json", parse_package_json(raw_content)
        return stype, []

    text = str(raw_content)
    # Try JSON first if applicable
    if stype in {"auto", "cyclonedx", "cyclonedx-json", "spdx", "spdx-json", "package-lock.json", "package.json"}:
        stripped = text.lstrip()
        if stripped.startswith("{"):
            try:
                parsed_json = json.loads(text)
                return parse_sbom_input(stype, parsed_json)
            except json.JSONDecodeError:
                pass

    if stype in {"requirements.txt", "pip", "requirements"}:
        return "requirements.txt", parse_requirements_txt(text)
    if stype in {"go.mod", "golang"}:
        return "go.mod", parse_go_mod(text)
    if stype in {"dockerfile", "docker"}:
        return "dockerfile", parse_dockerfile(text)

    # Auto-detect text formats
    if re.search(r"^\s*FROM\s+\S+", text, re.IGNORECASE | re.MULTILINE):
        return "dockerfile", parse_dockerfile(text)
    if re.search(r"^\s*module\s+\S+", text, re.MULTILINE) and "require" in text:
        return "go.mod", parse_go_mod(text)
    return "requirements.txt", parse_requirements_txt(text)


def export_cyclonedx(sbom: Any, components: list[Any], project_name: str = "SecureChain Project") -> dict[str, Any]:
    """Export an SBOM and its components in CycloneDX 1.5 JSON format."""
    cdx_components = []
    for comp in components:
        entry: dict[str, Any] = {
            "type": comp.type or "library",
            "bom-ref": comp.purl or f"{comp.name}@{comp.version}",
            "name": comp.name,
            "version": comp.version or "0.0.0",
        }
        if comp.purl:
            entry["purl"] = comp.purl
        if comp.author:
            entry["author"] = comp.author
        if comp.license:
            entry["licenses"] = [{"license": {"id": comp.license}}]
        hashes = (comp.metadata_ or {}).get("hashes") if isinstance(comp.metadata_, dict) else None
        if isinstance(hashes, dict) and hashes:
            entry["hashes"] = [{"alg": alg, "content": val} for alg, val in hashes.items() if val]
        cdx_components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{sbom.id}",
        "version": 1,
        "metadata": {
            "timestamp": utcnow_iso(),
            "tools": [{"vendor": "SecureChain", "name": "SecureChain SBOM Engine", "version": "1.1.0"}],
            "component": {"type": "application", "name": project_name, "version": sbom.version or "1.0"},
        },
        "components": cdx_components,
    }


def export_spdx(sbom: Any, components: list[Any], project_name: str = "SecureChain Project") -> dict[str, Any]:
    """Export an SBOM and its components in SPDX 2.3 JSON format."""
    packages = []
    for idx, comp in enumerate(components, start=1):
        pkg: dict[str, Any] = {
            "SPDXID": f"SPDXRef-Package-{idx}",
            "name": comp.name,
            "versionInfo": comp.version or "0.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": comp.license or "NOASSERTION",
            "licenseDeclared": comp.license or "NOASSERTION",
            "supplier": comp.author or "NOASSERTION",
        }
        if comp.purl:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }
            ]
        packages.append(pkg)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-sbom",
        "documentNamespace": f"https://securechain.local/spdx/{sbom.id}-{uuid4().hex[:8]}",
        "creationInfo": {
            "created": utcnow_iso(),
            "creators": ["Tool: SecureChain-1.1.0"],
        },
        "packages": packages,
    }


def diff_sboms(base_components: list[Any], head_components: list[Any]) -> dict[str, Any]:
    """Compute added, removed, and changed components between two SBOMs."""
    base_map = {c.name.lower(): c for c in base_components}
    head_map = {c.name.lower(): c for c in head_components}

    added = []
    removed = []
    changed = []
    unchanged_count = 0

    for key, head_comp in head_map.items():
        if key not in base_map:
            added.append({"name": head_comp.name, "version": head_comp.version, "purl": head_comp.purl})
        else:
            base_comp = base_map[key]
            if (base_comp.version or "") != (head_comp.version or ""):
                changed.append(
                    {
                        "name": head_comp.name,
                        "from_version": base_comp.version,
                        "to_version": head_comp.version,
                        "purl": head_comp.purl,
                    }
                )
            else:
                unchanged_count += 1

    for key, base_comp in base_map.items():
        if key not in head_map:
            removed.append({"name": base_comp.name, "version": base_comp.version, "purl": base_comp.purl})

    return {
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged_count,
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def evaluate_sbom_completeness(sbom: Any, components: list[Any]) -> dict[str, Any]:
    """
    Evaluate an SBOM against CISA Minimum Elements (NTIA / CISA 2026 baseline):
    name, version, unique identifier (PURL), supplier/author, cryptographic hash, license, timestamp.
    """
    total = len(components)
    if total == 0:
        return {
            "standard": "CISA-SBOM-2026",
            "completeness_score": 0.0,
            "grade": "F",
            "component_count": 0,
            "checks": {},
            "recommendations": ["Ingest components from lockfiles or CycloneDX/SPDX before compliance evaluation."],
        }

    with_version = sum(1 for c in components if c.version and c.version != "0.0.0")
    with_purl = sum(1 for c in components if c.purl)
    with_license = sum(1 for c in components if c.license)
    with_author = sum(1 for c in components if c.author)
    with_hashes = sum(
        1 for c in components if isinstance(c.metadata_, dict) and bool(c.metadata_.get("hashes"))
    )

    checks = {
        "component_names": 100.0,
        "component_versions": round((with_version / total) * 100, 1),
        "unique_identifiers_purl": round((with_purl / total) * 100, 1),
        "licenses_declared": round((with_license / total) * 100, 1),
        "supplier_or_author": round((with_author / total) * 100, 1),
        "cryptographic_hashes": round((with_hashes / total) * 100, 1),
        "sbom_timestamp": 100.0 if sbom.generated_at else 0.0,
    }
    score = round(sum(checks.values()) / len(checks), 1)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"

    recommendations = []
    if checks["unique_identifiers_purl"] < 100:
        recommendations.append("Ensure all components include standardized Package URLs (PURL).")
    if checks["cryptographic_hashes"] < 80:
        recommendations.append("Include SHA-256/SHA-512 integrity hashes (required by CISA 2026 SBOM elements).")
    if checks["licenses_declared"] < 80:
        recommendations.append("Populate SPDX license identifiers for IP and EU CRA compliance.")
    if checks["supplier_or_author"] < 80:
        recommendations.append("Record supplier/author metadata for software provenance.")

    return {
        "standard": "CISA-SBOM-2026",
        "completeness_score": score,
        "grade": grade,
        "component_count": total,
        "checks": checks,
        "recommendations": recommendations,
    }
