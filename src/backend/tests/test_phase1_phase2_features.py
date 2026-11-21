"""
Comprehensive tests for Phase 1 & Phase 2 features:
- Automated lockfile / SBOM parsing (CycloneDX, SPDX, package-lock.json, requirements.txt, go.mod, Dockerfile)
- CycloneDX & SPDX export, SBOM diffing, CISA 2026 completeness scoring
- Exact version-range vulnerability matching (no false positives on patched versions) + KEV/EPSS enrichment
- Real supply-chain threat detection (typosquatting, dependency confusion, install scripts, copyleft, AI-BOM pickle)
- Threat triage status persistence & contextual risk scoring
"""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, Project
from app.services.intel_service import is_version_affected
from app.services.risk_service import calculate_sbom_risk, get_component_recommendations
from app.services.sbom_parser import (
    diff_sboms,
    evaluate_sbom_completeness,
    export_cyclonedx,
    export_spdx,
    parse_sbom_input,
)
from app.services.sbom_service import create_sbom, list_components
from app.services.threat_service import build_threats_for_sbom, update_threat_status
from app.services.vulnerability_service import scan_sbom_vulnerabilities


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as db_session:
        yield db_session

    await engine.dispose()


@pytest.fixture
async def org_and_project(session: AsyncSession):
    org = Organization(name="Enterprise SecCorp")
    session.add(org)
    await session.flush()

    proj = Project(organization_id=org.id, name="Core API", slug="core-api", description="Main service")
    session.add(proj)
    await session.commit()
    return org, proj


def test_parse_multiple_ecosystems_and_formats():
    # requirements.txt
    fmt, py_comps = parse_sbom_input("requirements.txt", "requests==2.30.0\nfastapi>=0.110.0\n# comment\n")
    assert fmt == "requirements.txt"
    assert len(py_comps) == 2
    assert py_comps[0]["purl"] == "pkg:pypi/requests@2.30.0"

    # package-lock.json (v3)
    npm_lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.11", "license": "MIT", "integrity": "sha512-abc", "hasInstallScript": True},
        },
    }
    fmt, npm_comps = parse_sbom_input("auto", npm_lock)
    assert fmt == "package-lock.json"
    assert len(npm_comps) == 1
    assert npm_comps[0]["metadata"]["has_install_script"] is True
    assert npm_comps[0]["metadata"]["hashes"]["SHA-512"] == "sha512-abc"

    # go.mod
    go_mod = "module example.com/app\nrequire (\n\tgolang.org/x/net v0.15.0\n\tgithub.com/gin-gonic/gin v1.9.1 // indirect\n)\n"
    fmt, go_comps = parse_sbom_input("go.mod", go_mod)
    assert fmt == "go.mod"
    assert len(go_comps) == 2
    assert go_comps[0]["metadata"]["direct"] is True
    assert go_comps[1]["metadata"]["direct"] is False

    # Dockerfile
    fmt, docker_comps = parse_sbom_input("dockerfile", "FROM python:3.12-slim\nRUN echo hi\n")
    assert fmt == "dockerfile"
    assert len(docker_comps) == 1
    assert docker_comps[0]["type"] == "container"


def test_exact_version_range_matching():
    assert is_version_affected("2.14.0", fixed_version="2.17.1") is True
    assert is_version_affected("2.17.1", fixed_version="2.17.1") is False
    assert is_version_affected("2.20.0", fixed_version="2.17.1") is False
    # xz-utils CVE-2024-3094 only affects 5.6.0 - 5.6.1
    assert is_version_affected("5.4.6", fixed_version="5.6.2", min_affected="5.6.0") is False
    assert is_version_affected("5.6.1", fixed_version="5.6.2", min_affected="5.6.0") is True
    assert is_version_affected("5.6.2", fixed_version="5.6.2", min_affected="5.6.0") is False


async def test_vulnerability_scan_kev_epss_and_no_false_positives(session: AsyncSession, org_and_project):
    org, proj = org_and_project
    sbom = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "1.5",
        {"source": "upload"},
        components_data=[
            {"name": "log4j-core", "version": "2.14.0", "type": "library", "purl": "pkg:maven/log4j-core@2.14.0"},
            {"name": "requests", "version": "2.32.0", "type": "library", "purl": "pkg:pypi/requests@2.32.0"},  # Patched!
        ],
    )

    result = await scan_sbom_vulnerabilities(session, str(sbom.id), org.id, use_live_osv=False)
    assert result is not None
    assert result["findings_count"] == 1  # requests@2.32.0 must NOT be flagged
    assert result["kev_findings_count"] == 1
    finding = result["findings"][0]
    assert finding["component_name"] == "log4j-core"
    assert finding["vulnerability"]["in_kev"] is True
    assert finding["vulnerability"]["epss_score"] > 0.9

    risk = await calculate_sbom_risk(session, sbom.id)
    assert risk["overall_score"] >= 90.0
    assert risk["kev_count"] == 1
    assert risk["risk_grade"] == "F"

    comps = await list_components(session, str(sbom.id))
    log4j_comp = next(c for c in comps if c.name == "log4j-core")
    recs = await get_component_recommendations(session, log4j_comp.id)
    assert any("CISA KEV" in r["title"] and "2.17.1" in r["title"] for r in recs)


async def test_real_supply_chain_threats_and_triage(session: AsyncSession, org_and_project):
    org, proj = org_and_project
    sbom = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "1.5",
        {"source": "upload"},
        components_data=[
            {"name": "reqeusts", "version": "1.0.0", "type": "library", "purl": "pkg:pypi/reqeusts@1.0.0"},
            {"name": "corp-auth-utils", "version": "0.1.0", "type": "library", "purl": "pkg:npm/corp-auth-utils@0.1.0"},
            {"name": "evil-helper", "version": "1.0.0", "type": "library", "purl": "pkg:npm/evil-helper@1.0.0", "metadata": {"has_install_script": True}},
            {"name": "gpl-lib", "version": "2.0.0", "type": "library", "license": "AGPL-3.0-only"},
            {"name": "llama-weights.pkl", "version": "1.0", "type": "machine-learning-model"},
        ],
    )

    threats = await build_threats_for_sbom(session, sbom.id)
    types_found = {t["threat_type"] for t in threats}
    assert "typosquatting" in types_found
    assert "dependency-confusion" in types_found
    assert "behavioral-risk" in types_found
    assert "license-risk" in types_found
    assert "ai-supply-chain" in types_found

    # Verify triage persistence
    typo_threat = next(t for t in threats if t["threat_type"] == "typosquatting")
    updated = await update_threat_status(session, typo_threat["id"], org.id, "mitigated")
    assert updated is not None
    assert updated["status"] == "mitigated"


async def test_sbom_export_diff_and_cisa_completeness(session: AsyncSession, org_and_project):
    _, proj = org_and_project
    sbom_v1 = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "1.0",
        {},
        components_data=[
            {"name": "fastapi", "version": "0.104.0", "type": "library", "purl": "pkg:pypi/fastapi@0.104.0", "license": "MIT", "author": "tiangolo", "metadata": {"hashes": {"SHA-256": "abc"}}},
            {"name": "old-lib", "version": "1.0.0", "type": "library", "purl": "pkg:pypi/old-lib@1.0.0"},
        ],
    )
    sbom_v2 = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "2.0",
        {},
        components_data=[
            {"name": "fastapi", "version": "0.115.0", "type": "library", "purl": "pkg:pypi/fastapi@0.115.0", "license": "MIT", "author": "tiangolo", "metadata": {"hashes": {"SHA-256": "def"}}},
            {"name": "new-lib", "version": "2.0.0", "type": "library", "purl": "pkg:pypi/new-lib@2.0.0"},
        ],
    )

    v1_comps = await list_components(session, str(sbom_v1.id))
    v2_comps = await list_components(session, str(sbom_v2.id))

    cdx = export_cyclonedx(sbom_v1, v1_comps, proj.name)
    assert cdx["bomFormat"] == "CycloneDX"
    assert len(cdx["components"]) == 2

    spdx = export_spdx(sbom_v1, v1_comps, proj.name)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 2

    diff = diff_sboms(v1_comps, v2_comps)
    assert diff["summary"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 0}
    assert diff["changed"][0]["from_version"] == "0.104.0"
    assert diff["changed"][0]["to_version"] == "0.115.0"

    completeness = evaluate_sbom_completeness(sbom_v1, v1_comps)
    assert completeness["standard"] == "CISA-SBOM-2026"
    assert 0 < completeness["completeness_score"] <= 100
