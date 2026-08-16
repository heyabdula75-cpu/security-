import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, Organization, User, ComplianceFramework, PolicyStatus, ReportStatus, AuditAction
from app.services.compliance_service import (
    create_policy,
    get_policy,
    list_policies,
    update_policy,
    delete_policy,
    create_report,
    get_report,
    list_reports,
    update_report_status,
    create_audit_log,
    list_audit_logs,
)


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
async def seeded_organization(session: AsyncSession):
    organization = Organization(name="Compliance Org")
    session.add(organization)
    await session.commit()
    return organization


@pytest.fixture
async def seeded_user(session: AsyncSession, seeded_organization):
    user = User(
        email="compliance@example.com",
        password_hash="fake-hash",
        organization_id=seeded_organization.id,
    )
    session.add(user)
    await session.commit()
    return user


async def test_create_and_get_policy(session: AsyncSession, seeded_organization):
    policy = await create_policy(
        session,
        seeded_organization.id,
        ComplianceFramework.NIST,
        "PR.AC-1",
        "Access Control Policy",
        description="Policy for access control",
        requirements="Enable MFA for all users",
        metadata={"version": "1.0"},
    )

    assert policy is not None
    assert policy.control_id == "PR.AC-1"
    assert policy.metadata_ == {"version": "1.0"}

    fetched = await get_policy(session, policy.id)
    assert fetched is not None
    assert fetched.title == "Access Control Policy"
    assert fetched.metadata_ == {"version": "1.0"}


async def test_update_and_delete_policy(session: AsyncSession, seeded_organization):
    policy = await create_policy(
        session,
        seeded_organization.id,
        ComplianceFramework.SOC2,
        "CC6.1",
        "Physical Access Policy",
    )

    updated = await update_policy(
        session,
        policy.id,
        title="Updated Physical Access Policy",
        metadata_={"owner": "compliance-officer"},
    )

    assert updated is not None
    assert updated.title == "Updated Physical Access Policy"
    assert updated.metadata_ == {"owner": "compliance-officer"}

    deleted = await delete_policy(session, policy.id)
    assert deleted is True

    fetched = await get_policy(session, policy.id)
    assert fetched is None


async def test_compliance_reports(session: AsyncSession, seeded_organization, seeded_user):
    policy = await create_policy(
        session,
        seeded_organization.id,
        ComplianceFramework.ISO27001,
        "A.12.6.1",
        "Vulnerability Management Policy",
    )

    report = await create_report(
        session,
        seeded_organization.id,
        policy.id,
        "ISO27001 Vulnerability Scan Report",
        generated_by=seeded_user.id,
    )

    assert report is not None
    assert report.status == ReportStatus.PENDING

    updated_report = await update_report_status(
        session,
        report.id,
        status=ReportStatus.COMPLETED,
        compliance_score="95%",
        findings_count='{"high": 0, "medium": 2}',
        report_data={"scanned_items": 10},
    )

    assert updated_report is not None
    assert updated_report.status == ReportStatus.COMPLETED
    assert updated_report.compliance_score == "95%"

    reports = await list_reports(session, seeded_organization.id)
    assert len(reports) == 1
    assert reports[0].title == "ISO27001 Vulnerability Scan Report"


async def test_audit_logs(session: AsyncSession, seeded_organization, seeded_user):
    log = await create_audit_log(
        session,
        seeded_organization.id,
        AuditAction.SCAN,
        "sbom",
        "success",
        user_id=seeded_user.id,
        resource_name="production-sbom.json",
        details={"scanned_vulnerabilities": 5},
    )

    assert log is not None
    assert log.action == AuditAction.SCAN
    assert log.status == "success"

    logs = await list_audit_logs(session, seeded_organization.id)
    assert len(logs) == 1
    assert logs[0].resource_name == "production-sbom.json"
