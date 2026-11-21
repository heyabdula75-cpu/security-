#!/usr/bin/env python3
"""
One-Command Enterprise Demo Seeder for SecureChain.
Creates a realistic demo organization, user (demo@securechain.io / SecureChain2026!),
3 projects, SBOMs (Web API, AI/LLM Pipeline, Container Base), live KEV/EPSS findings,
supply-chain threats, OpenVEX attestations, SLSA signature, and a scoped CI/CD API key.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src" / "backend"))

from sqlalchemy import select

from app.database import session_manager
from app.db_init import initialize_database_from_settings
from app.models import Organization, Project, User
from app.services.enterprise_service import create_api_key, sign_sbom
from app.services.sbom_service import create_sbom
from app.services.threat_service import build_threats_for_sbom
from app.services.vex_service import create_vex_statement
from app.services.vulnerability_service import scan_sbom_vulnerabilities
from app.utils.password_utils import get_password_hash


async def seed() -> None:
    await initialize_database_from_settings()
    async_session = session_manager._get_session_factory()
    async with async_session() as db:
        existing = (await db.execute(select(User).where(User.email == "demo@securechain.io"))).scalars().first()
        if existing:
            print("Demo user demo@securechain.io already exists. Nothing to re-seed.")
            return

        org = Organization(name="Acme Enterprise Security")
        db.add(org)
        await db.flush()

        user = User(
            organization_id=org.id,
            email="demo@securechain.io",
            full_name="Alex Mercer (CISO)",
            password_hash=get_password_hash("SecureChain2026!"),
            is_active=True,
        )
        db.add(user)
        await db.flush()

        p1 = Project(organization_id=org.id, name="payments-gateway", slug="payments-gateway", description="Core PCI-DSS payments API")
        p2 = Project(organization_id=org.id, name="llm-copilot-service", slug="llm-copilot-service", description="Production RAG & LLM inference service")
        p3 = Project(organization_id=org.id, name="edge-container-base", slug="edge-container-base", description="Hardened Kubernetes base image")
        db.add_all([p1, p2, p3])
        await db.commit()

        sbom1 = await create_sbom(
            db, str(p1.id), "cyclonedx-json", "2.4.0", {"source": "github-actions"},
            components_data=[
                {"name": "log4j-core", "version": "2.14.0", "type": "library", "purl": "pkg:maven/log4j-core@2.14.0", "license": "Apache-2.0", "author": "Apache", "metadata": {"hashes": {"SHA-256": "a1b2c3"}}},
                {"name": "lodash", "version": "4.17.11", "type": "library", "purl": "pkg:npm/lodash@4.17.11", "license": "MIT", "author": "OpenJS", "metadata": {"hashes": {"SHA-256": "d4e5f6"}}},
                {"name": "reqeusts", "version": "1.0.0", "type": "library", "purl": "pkg:pypi/reqeusts@1.0.0", "license": "MIT"},
                {"name": "fastapi", "version": "0.115.0", "type": "library", "purl": "pkg:pypi/fastapi@0.115.0", "license": "MIT", "author": "tiangolo", "metadata": {"hashes": {"SHA-256": "f7g8h9"}}},
            ],
        )
        sbom2 = await create_sbom(
            db, str(p2.id), "cyclonedx-json", "1.2.0", {"source": "ml-pipeline"},
            components_data=[
                {"name": "requests", "version": "2.30.0", "type": "library", "purl": "pkg:pypi/requests@2.30.0", "license": "Apache-2.0", "author": "PSF", "metadata": {"hashes": {"SHA-256": "112233"}}},
                {"name": "llama-3-8b.safetensors", "version": "1.0", "type": "machine-learning-model", "purl": "pkg:huggingface/meta-llama/llama-3-8b@1.0", "license": "Llama-3", "author": "Meta", "metadata": {"model_card": "https://huggingface.co/meta-llama", "hashes": {"SHA-256": "445566"}}},
                {"name": "legacy-classifier.pkl", "version": "0.9", "type": "machine-learning-model", "purl": "pkg:generic/legacy-classifier@0.9"},
            ],
        )
        sbom3 = await create_sbom(
            db, str(p3.id), "dockerfile", "3.12-slim", {"source": "Dockerfile"},
            components_data=[
                {"name": "python", "version": "3.12-slim", "type": "container", "purl": "pkg:oci/python@3.12-slim", "license": "PSF", "author": "Docker Official", "metadata": {"hashes": {"SHA-256": "778899"}}},
            ],
        )

        for sb in (sbom1, sbom2, sbom3):
            await scan_sbom_vulnerabilities(db, str(sb.id), org.id, use_live_osv=False)
            await build_threats_for_sbom(db, sb.id)

        await create_vex_statement(
            db, org.id, sbom1.id, "CVE-2019-10744", "not_affected",
            component_name="lodash", component_purl="pkg:npm/lodash@4.17.11",
            justification="vulnerable_code_not_in_execute_path",
            impact_statement="AST reachability confirmed defaultsDeep is never called.",
            author=user.email,
        )
        await sign_sbom(db, sbom3.id, org.id, signer=user.email, slsa_level="SLSA_BUILD_L3")
        _, raw_key = await create_api_key(db, org.id, user.id, "GitHub Actions CI Key")

        print("=== SecureChain Enterprise Demo Seeded ===")
        print("Login Email : demo@securechain.io")
        print("Password    : SecureChain2026!")
        print(f"CI API Key  : {raw_key}")
        print(f"Project IDs : payments-gateway={p1.id}, llm-copilot={p2.id}, edge-base={p3.id}")


if __name__ == "__main__":
    asyncio.run(seed())
