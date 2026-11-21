"""
Tests for Option A (Enterprise Backend Powerhouse):
- AI Security Copilot (live KEV, compliance, and threat queries)
- Deep AI-BOM / Pickle opcode static scanner & HuggingFace/PyTorch loader scanner
- Scoped API Keys (create, hash verification, revoke)
- Cryptographic SBOM Signing & Tamper Detection (HMAC-SHA256 DSSE + SLSA)
- Auto-Fix Patch & PR Diff Generator
- One-Click Regulatory Audit Evidence Bundle
- Webhooks CRUD
"""
import base64
import pickle

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Component, Organization, Project
from app.services.copilot_service import query_security_copilot, scan_ai_bom_artifact
from app.services.enterprise_service import (
    build_audit_evidence_bundle,
    create_api_key,
    create_webhook,
    delete_webhook,
    generate_autofix_patches,
    list_api_keys,
    list_webhooks,
    revoke_api_key,
    sign_sbom,
    verify_api_key,
    verify_sbom_signature,
)
from app.services.sbom_service import create_sbom
from app.services.threat_service import build_threats_for_sbom
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
async def seeded_env(session: AsyncSession):
    org = Organization(name="Global FinTech")
    session.add(org)
    await session.flush()

    proj = Project(organization_id=org.id, name="Payments Core", slug="payments-core")
    session.add(proj)
    await session.commit()

    sbom = await create_sbom(
        session,
        str(proj.id),
        "cyclonedx-json",
        "1.5",
        {},
        components_data=[
            {"name": "log4j-core", "version": "2.14.0", "type": "library", "purl": "pkg:maven/log4j-core@2.14.0", "license": "Apache-2.0"},
            {"name": "requests", "version": "2.30.0", "type": "library", "purl": "pkg:pypi/requests@2.30.0", "license": "Apache-2.0"},
            {"name": "reqeusts", "version": "1.0.0", "type": "library", "purl": "pkg:pypi/reqeusts@1.0.0"},
        ],
    )
    await scan_sbom_vulnerabilities(session, str(sbom.id), org.id, use_live_osv=False)
    await build_threats_for_sbom(session, sbom.id)
    return org, proj, sbom


def test_deep_ai_bom_pickle_and_loader_scanner():
    # Craft a benign-in-test pickle payload that references os.system (NEVER executed — statically disassembled!)
    class _MaliciousPayload:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))

    raw_pickle = pickle.dumps(_MaliciousPayload())
    b64 = base64.b64encode(raw_pickle).decode("ascii")

    res = scan_ai_bom_artifact("weights.pkl", content_base64=b64)
    assert res["risk_level"] == "critical"
    assert res["findings_count"] >= 1
    assert any(f["rule_id"] == "AIBOM-PICKLE-RCE" for f in res["findings"])

    # Scan unsafe PyTorch + HuggingFace loader code
    py_code = "model = AutoModel.from_pretrained('org/model', trust_remote_code=True)\nw = torch.load('model.pt')\n"
    res2 = scan_ai_bom_artifact("load_model.py", content_text=py_code)
    assert res2["risk_level"] == "critical"
    rule_ids = {f["rule_id"] for f in res2["findings"]}
    assert "AIBOM-REMOTE-CODE" in rule_ids
    assert "AIBOM-UNSAFE-TORCH-LOAD" in rule_ids


async def test_ai_security_copilot_live_queries(session: AsyncSession, seeded_env):
    org, _, _ = seeded_env

    kev_ans = await query_security_copilot(session, org.id, "Which packages have CISA KEV vulnerabilities?")
    assert kev_ans["intent"] == "kev_and_critical_exposure"
    assert "CVE-2021-44228" in kev_ans["answer"]
    assert kev_ans["context_metrics"]["kev_count"] == 1

    comp_ans = await query_security_copilot(session, org.id, "Draft an EU CRA executive compliance summary")
    assert comp_ans["intent"] == "compliance_and_executive_summary"
    assert "EU Cyber Resilience Act" in comp_ans["answer"]

    threat_ans = await query_security_copilot(session, org.id, "Show typosquatting threats")
    assert threat_ans["intent"] == "supply_chain_threats"
    assert "typosquatting" in threat_ans["answer"]


async def test_scoped_api_keys_and_webhooks(session: AsyncSession, seeded_env):
    org, _, _ = seeded_env

    record, raw_key = await create_api_key(session, org.id, None, "GitHub CI Key", ["scan:write", "sbom:read"])
    assert raw_key.startswith("sc_live_")
    assert len(await list_api_keys(session, org.id)) == 1

    verified = await verify_api_key(session, raw_key)
    assert verified is not None
    assert verified.id == record.id

    assert await revoke_api_key(session, record.id, org.id) is True
    assert await verify_api_key(session, raw_key) is None

    hook = await create_webhook(session, org.id, "Slack SecOps", "https://hooks.slack.example/test")
    assert len(await list_webhooks(session, org.id)) == 1
    assert await delete_webhook(session, hook.id, org.id) is True
    assert len(await list_webhooks(session, org.id)) == 0


async def test_cryptographic_signing_tamper_detection_autofix_and_audit_bundle(session: AsyncSession, seeded_env):
    org, _, sbom = seeded_env

    # Sign & verify clean SBOM
    sig = await sign_sbom(session, sbom.id, org.id, signer="secops@fintech.com")
    assert sig is not None
    assert sig["slsa_level"] == "SLSA_BUILD_L2"

    v1 = await verify_sbom_signature(session, sbom.id, org.id)
    assert v1["verified"] is True
    assert v1["tampered"] is False

    # Auto-fix patches
    autofix = await generate_autofix_patches(session, sbom.id, org.id)
    assert autofix is not None
    assert autofix["patch_count"] == 2
    assert any(p["component_name"] == "log4j-core" and p["fixed_version"] == "2.17.1" for p in autofix["patches"])

    # Audit Evidence Bundle
    bundle = await build_audit_evidence_bundle(session, org.id, sbom.id, signer="secops@fintech.com")
    assert bundle is not None
    assert bundle["sbom_cyclonedx"]["bomFormat"] == "CycloneDX"
    assert bundle["vex_openvex"]["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert bundle["cryptographic_attestation"]["signature"]

    # Tamper with SBOM by injecting an unauthorized component -> verification MUST fail!
    session.add(Component(sbom_id=sbom.id, name="injected-backdoor", version="9.9.9", type="library"))
    await session.commit()

    v2 = await verify_sbom_signature(session, sbom.id, org.id)
    assert v2["verified"] is False
    assert v2["tampered"] is True
