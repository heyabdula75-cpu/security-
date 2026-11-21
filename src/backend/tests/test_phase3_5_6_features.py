"""
Tests for Phases 3, 5, and 6:
- Phase 3: VEX (OpenVEX v0.2.0 & CycloneDX 1.5 VEX) + Python & JS/TS AST Reachability Analyzer
- Phase 5: Standalone securechain-cli (discovery, SARIF 2.1.0, CycloneDX, PR Markdown, CI Policy Gate)
- Phase 6: Automated Regulatory Compliance Evaluator (EU CRA, CISA 2026, FDA 524B, EU AI Act, NIST SSDF)
"""
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, Project
from app.services.compliance_evaluator import evaluate_organization_compliance
from app.services.reachability_service import evaluate_reachability
from app.services.sbom_service import create_sbom
from app.services.threat_service import build_threats_for_sbom
from app.services.vex_service import (
    create_vex_statement,
    export_cyclonedx_vex,
    export_openvex,
    list_vex_statements,
)
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
async def org_project_sbom(session: AsyncSession):
    org = Organization(name="Tier1 Tech")
    session.add(org)
    await session.flush()

    proj = Project(organization_id=org.id, name="AI Platform", slug="ai-platform")
    session.add(proj)
    await session.commit()

    sbom = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "1.5",
        {},
        components_data=[
            {
                "name": "log4j-core",
                "version": "2.14.0",
                "type": "library",
                "purl": "pkg:maven/log4j-core@2.14.0",
                "license": "Apache-2.0",
                "author": "Apache",
                "metadata": {"hashes": {"SHA-256": "abc123"}},
            },
            {
                "name": "lodash",
                "version": "4.17.11",
                "type": "library",
                "purl": "pkg:npm/lodash@4.17.11",
                "license": "MIT",
                "author": "OpenJS",
                "metadata": {"hashes": {"SHA-256": "def456"}},
            },
            {
                "name": "requests",
                "version": "2.30.0",
                "type": "library",
                "purl": "pkg:pypi/requests@2.30.0",
                "license": "Apache-2.0",
                "author": "PSF",
                "metadata": {"hashes": {"SHA-256": "ghi789"}},
            },
            {
                "name": "llama-3-8b.safetensors",
                "version": "1.0",
                "type": "machine-learning-model",
                "purl": "pkg:huggingface/meta-llama/llama-3-8b@1.0",
                "license": "Llama-3",
                "author": "Meta",
                "metadata": {"model_card": "https://huggingface.co/meta-llama", "hashes": {"SHA-256": "modelhash"}},
            },
        ],
    )
    await scan_sbom_vulnerabilities(session, str(sbom.id), org.id, use_live_osv=False)
    await build_threats_for_sbom(session, sbom.id)
    return org, proj, sbom


def test_python_and_js_ast_reachability():
    files = {
        "backend/client.py": "import requests\nresp = requests.get('https://example.com')\n",
        "frontend/util.js": "import _ from 'lodash';\nconst x = _.cloneDeep({});\n",
    }
    findings = [
        {"component_name": "requests", "cve_id": "CVE-2023-32681"},  # reachable (requests.get called)
        {"component_name": "lodash", "cve_id": "CVE-2019-10744"},    # unreachable (defaultsDeep NOT called)
        {"component_name": "moment", "cve_id": "CVE-2022-31129"},    # unreachable (not imported)
    ]

    report = evaluate_reachability(files, findings)
    assert report["reachable_count"] == 1
    assert report["unreachable_count"] == 2
    assert report["noise_reduction_percent"] == pytest.approx(66.7, rel=0.05)

    by_cve = {r["cve_id"]: r for r in report["results"]}
    assert by_cve["CVE-2023-32681"]["reachability"] == "reachable"
    assert by_cve["CVE-2019-10744"]["reachability"] == "unreachable"
    assert by_cve["CVE-2019-10744"]["recommended_vex_status"] == "not_affected"
    assert by_cve["CVE-2022-31129"]["reachability"] == "unreachable"


async def test_vex_crud_and_exports(session: AsyncSession, org_project_sbom):
    org, _, sbom = org_project_sbom
    stmt = await create_vex_statement(
        session,
        organization_id=org.id,
        sbom_id=sbom.id,
        cve_id="CVE-2019-10744",
        status="not_affected",
        component_name="lodash",
        component_purl="pkg:npm/lodash@4.17.11",
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="defaultsDeep is never invoked.",
    )
    listed = await list_vex_statements(session, org.id, sbom_id=sbom.id)
    assert len(listed) == 1
    assert listed[0].id == stmt.id

    openvex = export_openvex(str(sbom.id), listed)
    assert openvex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert openvex["statements"][0]["status"] == "not_affected"

    cdx_vex = export_cyclonedx_vex(str(sbom.id), listed)
    assert cdx_vex["bomFormat"] == "CycloneDX"
    assert cdx_vex["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


async def test_automated_compliance_evaluator_and_vex_impact(session: AsyncSession, org_project_sbom):
    org, _, sbom = org_project_sbom

    before = await evaluate_organization_compliance(session, org.id)
    framework_codes = {f["framework"] for f in before["frameworks"]}
    assert framework_codes == {"EU_CRA", "CISA_2026", "FDA_524B", "EU_AI_ACT", "NIST_SSDF"}
    assert before["scope"]["kev_vulnerabilities"] == 1

    # Attest KEV CVE as fixed/not_affected via VEX -> compliance score should improve!
    await create_vex_statement(
        session,
        organization_id=org.id,
        sbom_id=sbom.id,
        cve_id="CVE-2021-44228",
        status="not_affected",
        component_name="log4j-core",
        justification="vulnerable_code_not_in_execute_path",
    )
    after = await evaluate_organization_compliance(session, org.id)
    assert after["scope"]["kev_vulnerabilities"] == 0
    assert after["overall_compliance_score"] > before["overall_compliance_score"]


def test_standalone_cli_scan_sarif_and_policy_gate(tmp_path: Path):
    # Create a miniature repo with vulnerable + typosquatted deps & source file
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\nreqeusts==1.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import requests\nrequests.get('https://example.com')\n", encoding="utf-8")

    cli_path = Path(__file__).resolve().parents[3] / "cli" / "securechain_cli.py"
    spec = importlib.util.spec_from_file_location("securechain_cli", cli_path)
    cli = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(cli)

    sarif_out = tmp_path / "out.sarif"
    cdx_out = tmp_path / "sbom.json"
    md_out = tmp_path / "pr.md"

    # Should fail when --fail-on typosquat is set
    exit_code = cli.main([
        "scan",
        str(tmp_path),
        "--fail-on", "typosquat",
        "--sarif", str(sarif_out),
        "--cyclonedx", str(cdx_out),
        "--markdown", str(md_out),
    ])
    assert exit_code == 1
    assert sarif_out.exists()
    assert cdx_out.exists()
    assert "SecureChain Supply Chain Security Gate" in md_out.read_text(encoding="utf-8")

    # Should pass when --fail-on kev (no KEV in this temp repo)
    exit_code_kev = cli.main(["scan", str(tmp_path), "--fail-on", "kev"])
    assert exit_code_kev == 0
