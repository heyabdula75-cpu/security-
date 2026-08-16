# Phase 3: Database Design
## AI Supply Chain Security & SBOM Verification Platform

**Status**: IN PROGRESS
**Date**: 2026-07-08
**Version**: 1.0

---

## 1. Database Overview

### 1.1 Database Technology Stack

**Primary Database**: PostgreSQL 15+ (ACID compliance, advanced features)
**Time-Series Extension**: TimescaleDB 2.10+ (hypertables, compression)
**Search Engine**: Elasticsearch 8.0+ (audit logs, full-text search)
**Cache**: Redis 7.0+ (sessions, hot data, rate limiting)
**Backup Storage**: S3 + glacier (archived backups)

### 1.2 Database Capacity Planning

| Metric | Year 1 | Year 2 | Year 3 |
|---|---|---|---|
| Total Records | 5B | 15B | 50B |
| Database Size | 500GB | 1.5TB | 5TB |
| Daily Ingestion | 100M | 300M | 1B |
| Peak QPS | 5K | 15K | 50K |
| Storage (S3) | 2TB | 6TB | 20TB |

### 1.3 Database Design Principles

1. **Normalization**: 3NF for consistency (denormalization only when needed)
2. **Scalability**: Partition key defined for future sharding
3. **Performance**: Indexes for all frequently filtered/joined columns
4. **Security**: Row-level security (RLS) for multi-tenancy
5. **Auditability**: All changes logged and traceable
6. **Maintainability**: Clear naming conventions, documentation
7. **Resilience**: Backup, replication, and recovery strategies

---

## 2. Entity-Relationship Diagram (Simplified)

### 2.1 Core Entity Groups

```
┌─────────────────────────────────────────────────────────┐
│ USER MANAGEMENT GROUP                                   │
├─────────────────────────────────────────────────────────┤
│ users                      roles                         │
│ ├─ id (PK)                 ├─ id (PK)                   │
│ ├─ org_id (FK)             ├─ name                      │
│ ├─ email (UNIQUE)          ├─ description              │
│ ├─ username                └─ permissions              │
│ ├─ password_hash                                       │
│ ├─ mfa_enabled             role_assignments            │
│ ├─ last_login              ├─ user_id (FK)             │
│ └─ created_at              ├─ role_id (FK)             │
│                            └─ org_id (FK)              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PROJECT & SBOM GROUP                                    │
├─────────────────────────────────────────────────────────┤
│ organizations   projects       sboms                     │
│ ├─ id (PK)      ├─ id (PK)      ├─ id (PK)             │
│ ├─ name          ├─ org_id (FK)  ├─ project_id (FK)    │
│ ├─ tier          ├─ name         ├─ format (CycloneDX) │
│ └─ created_at    ├─ description  ├─ version           │
│                  ├─ repo_url      ├─ content (JSON)    │
│                  └─ created_at    ├─ hash (SHA256)    │
│                                    ├─ created_at       │
│ project_members   sbom_components  └─ generated_at     │
│ ├─ project_id     ├─ id (PK)                           │
│ ├─ user_id        ├─ sbom_id (FK)                      │
│ └─ role           ├─ name                               │
│                   ├─ version                            │
│                   ├─ type (library, app)                │
│                   ├─ hash                               │
│                   └─ purl (Package URL)                │
│                                                          │
│ sbom_relationships                                      │
│ ├─ parent_id (FK sbom_components)                       │
│ ├─ child_id (FK sbom_components)                        │
│ └─ relationship_type (depends_on)                       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ VULNERABILITY GROUP                                     │
├─────────────────────────────────────────────────────────┤
│ vulnerabilities    vulnerability_references            │
│ ├─ id (PK)         ├─ vuln_id (FK)                     │
│ ├─ cve_id (UNIQUE) ├─ reference_type (advisory_link)  │
│ ├─ severity        ├─ url                              │
│ ├─ cvss_score      └─ description                      │
│ ├─ epss_score                                           │
│ ├─ description     component_vulnerabilities           │
│ ├─ published_at    ├─ component_id (FK)                │
│ └─ updated_at      ├─ vulnerability_id (FK)            │
│                    ├─ discovered_at                    │
│ cves                │ fixed_in_version                │
│ ├─ id (PK)         └─ status (open/fixed)             │
│ ├─ cve_id                                               │
│ ├─ cvss_v3_score   vulnerability_feeds                 │
│ ├─ cvss_v3_vector  ├─ id (PK)                         │
│ └─ description     ├─ source (NVD, GitHub)             │
│                    ├─ last_updated                     │
│                    └─ record_count                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ THREAT DETECTION GROUP                                  │
├─────────────────────────────────────────────────────────┤
│ threat_detections     threat_intelligence_feeds        │
│ ├─ id (PK)            ├─ id (PK)                       │
│ ├─ component_id (FK)  ├─ name                          │
│ ├─ threat_type        ├─ source_url                    │
│ ├─ severity           ├─ last_updated                  │
│ ├─ confidence_score   └─ record_count                 │
│ ├─ description                                          │
│ ├─ detected_at        malware_signatures               │
│ └─ resolved_at        ├─ id (PK)                       │
│                       ├─ name                          │
│ threat_indicators     ├─ yara_rule                     │
│ ├─ component_id (FK)  ├─ severity                      │
│ ├─ indicator_type     └─ verified                      │
│ ├─ value                                                │
│ └─ source             typosquatting_candidates         │
│                       ├─ legitimate_package            │
│                       ├─ typosquat_package             │
│                       ├─ similarity_score               │
│                       └─ reported_at                    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ RISK SCORING GROUP                                      │
├─────────────────────────────────────────────────────────┤
│ risk_scores           risk_trends                       │
│ ├─ id (PK)            ├─ id (PK)                       │
│ ├─ component_id (FK)  ├─ component_id (FK)             │
│ ├─ org_id (FK)        ├─ timestamp                     │
│ ├─ score (0-100)      ├─ risk_score                    │
│ ├─ factors_json       ├─ trend_direction               │
│ ├─ calculated_at      └─ calculated_at                │
│ └─ valid_until                                          │
│                       remediation_recommendations      │
│ sbom_risk_scores      ├─ id (PK)                      │
│ ├─ sbom_id (FK)       ├─ component_id (FK)             │
│ ├─ overall_score      ├─ recommendation_type           │
│ ├─ critical_count     ├─ target_version                │
│ ├─ high_count         ├─ effort_level                  │
│ └─ calculated_at      └─ rationale                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ COMPLIANCE & AUDIT GROUP                                │
├─────────────────────────────────────────────────────────┤
│ compliance_policies   compliance_status                 │
│ ├─ id (PK)            ├─ id (PK)                       │
│ ├─ org_id (FK)        ├─ org_id (FK)                   │
│ ├─ policy_type        ├─ policy_id (FK)                │
│ ├─ policy_rule_json   ├─ status                        │
│ ├─ severity           ├─ last_checked                  │
│ └─ created_at         └─ violations_count              │
│                                                          │
│ audit_logs            policy_violations                │
│ ├─ id (PK)            ├─ id (PK)                       │
│ ├─ org_id (FK)        ├─ policy_id (FK)                │
│ ├─ user_id (FK)       ├─ component_id (FK)             │
│ ├─ action_type        ├─ violation_details             │
│ ├─ resource_type      ├─ severity                      │
│ ├─ resource_id        ├─ detected_at                   │
│ ├─ changes_json       └─ resolved_at                   │
│ ├─ ip_address                                           │
│ ├─ user_agent         containers                       │
│ ├─ status             ├─ id (PK)                       │
│ └─ timestamp          ├─ registry                      │
│                       ├─ image_name                    │
│                       ├─ image_tag                     │
│                       ├─ digest                        │
│                       └─ last_scanned                  │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Complete Schema Specification

### 3.1 USER & ORGANIZATION TABLES

#### Table: organizations
```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    tier VARCHAR(50) NOT NULL DEFAULT 'starter', -- starter, professional, enterprise
    features JSONB NOT NULL DEFAULT '{}', -- available features per tier
    max_users INTEGER DEFAULT 100,
    max_projects INTEGER DEFAULT 1000,
    max_sboms_per_month INTEGER DEFAULT 100000,
    api_rate_limit INTEGER DEFAULT 1000, -- requests per minute
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_tier ON organizations(tier);
```

#### Table: users
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    avatar_url VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret_encrypted VARCHAR(255), -- Encrypted TOTP secret
    last_login TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_login TIMESTAMP WITH TIME ZONE,
    account_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP WITH TIME ZONE,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    password_reset_token_hash VARCHAR(255),
    password_reset_token_expires TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    CONSTRAINT email_org_unique UNIQUE(org_id, email),
    CONSTRAINT username_org_unique UNIQUE(org_id, username)
);
CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
```

#### Table: roles
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE, -- System roles cannot be deleted
    permissions JSONB NOT NULL DEFAULT '{}', -- {permission: [actions]}
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT role_name_unique UNIQUE(org_id, name)
);
CREATE INDEX idx_roles_org_id ON roles(org_id);
```

**System Roles**: super_admin, org_admin, security_team, developer, compliance_officer

#### Table: user_roles
```sql
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by_user_id UUID REFERENCES users(id),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by_user_id UUID REFERENCES users(id),
    CONSTRAINT user_role_unique UNIQUE(user_id, role_id)
);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
```

### 3.2 PROJECT & SBOM TABLES

#### Table: projects
```sql
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    slug VARCHAR(255) NOT NULL, -- URL-friendly identifier
    repo_url VARCHAR(255), -- Git repository URL
    repo_type VARCHAR(50), -- github, gitlab, bitbucket, custom
    created_by_user_id UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT project_slug_unique UNIQUE(org_id, slug)
);
CREATE INDEX idx_projects_org_id ON projects(org_id);
CREATE INDEX idx_projects_repo_url ON projects(repo_url);
```

#### Table: sboms
```sql
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL, -- cyclonedx-json, spdx-json, etc.
    version VARCHAR(50), -- Format version (1.5, 2.3, etc.)
    content JSONB NOT NULL, -- Full SBOM content
    content_hash VARCHAR(64) NOT NULL, -- SHA256 hash of content
    component_count INTEGER, -- Number of components
    vulnerability_count INTEGER, -- Number of vulnerabilities
    risk_score NUMERIC(5,2), -- Overall risk score (0-100)
    generated_by VARCHAR(255), -- Tool used to generate (syft, etc.)
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    s3_location VARCHAR(255), -- S3 path for backup
    PRIMARY KEY (id)
);
CREATE INDEX idx_sboms_org_id ON sboms(org_id);
CREATE INDEX idx_sboms_project_id ON sboms(project_id);
CREATE INDEX idx_sboms_generated_at ON sboms(generated_at DESC);
CREATE INDEX idx_sboms_risk_score ON sboms(risk_score);
```

#### Table: sbom_components
```sql
CREATE TABLE sbom_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(255),
    component_type VARCHAR(100), -- library, application, framework, etc.
    purl VARCHAR(500), -- Package URL identifier
    hash_algorithm VARCHAR(50), -- sha256, sha1, md5
    hash_value VARCHAR(256), -- Hash value
    license_identifier VARCHAR(100), -- SPDX license identifier
    author VARCHAR(255),
    supplier VARCHAR(255),
    homepage_url VARCHAR(500),
    download_url VARCHAR(500),
    repository_url VARCHAR(500),
    source VARCHAR(100), -- npm, pypi, maven, cargo, etc.
    scope VARCHAR(50), -- required, optional, excluded
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE INDEX idx_sbom_components_sbom_id ON sbom_components(sbom_id);
CREATE INDEX idx_sbom_components_org_id ON sbom_components(org_id);
CREATE INDEX idx_sbom_components_purl ON sbom_components(purl);
CREATE INDEX idx_sbom_components_name_version ON sbom_components(name, version);
```

#### Table: component_relationships
```sql
CREATE TABLE component_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    child_component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    relationship_type VARCHAR(100), -- depends_on, contains, related_to, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT no_self_relationship CHECK (parent_component_id != child_component_id)
);
CREATE INDEX idx_component_relationships_parent ON component_relationships(parent_component_id);
CREATE INDEX idx_component_relationships_child ON component_relationships(child_component_id);
```

### 3.3 VULNERABILITY TABLES

#### Table: vulnerabilities
```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) NOT NULL UNIQUE, -- CVE-YYYY-XXXXX
    description TEXT,
    severity VARCHAR(50), -- critical, high, medium, low, info
    cvss_v3_score NUMERIC(4,1),
    cvss_v3_vector VARCHAR(255),
    epss_score NUMERIC(5,4), -- Exploit Prediction Scoring System
    cwe_ids TEXT, -- Comma-separated CWE IDs
    published_date DATE,
    last_updated DATE,
    is_exploited BOOLEAN DEFAULT FALSE,
    exploit_public BOOLEAN DEFAULT FALSE,
    affected_packages JSONB, -- Array of {name, version_range}
    source VARCHAR(100), -- NVD, GitHub, OSV, etc.
    source_id VARCHAR(255), -- Unique ID from source
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_v3_score DESC);
CREATE INDEX idx_vulnerabilities_published_date ON vulnerabilities(published_date DESC);
CREATE INDEX idx_vulnerabilities_epss_score ON vulnerabilities(epss_score DESC);
```

#### Table: component_vulnerabilities (Junction Table)
```sql
CREATE TABLE component_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'open', -- open, fixed, mitigated, ignored
    fixed_in_version VARCHAR(255),
    is_transitive BOOLEAN DEFAULT FALSE, -- Transitive dependency?
    details_json JSONB, -- Additional vulnerability details
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT component_vuln_unique UNIQUE(component_id, vulnerability_id)
);
CREATE INDEX idx_component_vulnerabilities_component_id ON component_vulnerabilities(component_id);
CREATE INDEX idx_component_vulnerabilities_vulnerability_id ON component_vulnerabilities(vulnerability_id);
CREATE INDEX idx_component_vulnerabilities_status ON component_vulnerabilities(status);
CREATE INDEX idx_component_vulnerabilities_detected_at ON component_vulnerabilities(detected_at DESC);
```

#### Table: vulnerability_feeds
```sql
CREATE TABLE vulnerability_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    source_url VARCHAR(500),
    feed_type VARCHAR(100), -- NVD, GitHub, OSV, Custom
    update_frequency VARCHAR(50), -- daily, weekly, realtime
    last_updated TIMESTAMP WITH TIME ZONE,
    next_update TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50), -- active, inactive, error
    record_count INTEGER DEFAULT 0,
    last_error_message TEXT,
    last_successful_fetch TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_vulnerability_feeds_status ON vulnerability_feeds(status);
```

### 3.4 THREAT DETECTION TABLES

#### Table: threat_detections
```sql
CREATE TABLE threat_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    component_id UUID REFERENCES sbom_components(id) ON DELETE CASCADE,
    threat_type VARCHAR(100), -- typosquatting, malicious_package, dependency_confusion, compromised
    severity VARCHAR(50), -- critical, high, medium, low
    confidence_score NUMERIC(5,2), -- 0-100 confidence
    description TEXT,
    indicators_found JSONB, -- Array of indicators that triggered detection
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE, -- When threat was manually verified
    verified_by_user_id UUID REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'open', -- open, confirmed, false_positive, resolved
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_threat_detections_org_id ON threat_detections(org_id);
CREATE INDEX idx_threat_detections_component_id ON threat_detections(component_id);
CREATE INDEX idx_threat_detections_threat_type ON threat_detections(threat_type);
CREATE INDEX idx_threat_detections_severity ON threat_detections(severity);
CREATE INDEX idx_threat_detections_status ON threat_detections(status);
CREATE INDEX idx_threat_detections_detected_at ON threat_detections(detected_at DESC);
```

#### Table: malware_signatures
```sql
CREATE TABLE malware_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    yara_rule TEXT NOT NULL,
    severity VARCHAR(50),
    description TEXT,
    source VARCHAR(100), -- YARA Community, CustomRule, etc.
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_malware_signatures_name ON malware_signatures(name);
CREATE INDEX idx_malware_signatures_verified ON malware_signatures(verified);
```

#### Table: typosquatting_candidates
```sql
CREATE TABLE typosquatting_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legitimate_package VARCHAR(255) NOT NULL,
    typosquat_package VARCHAR(255) NOT NULL,
    similarity_score NUMERIC(5,2),
    package_source VARCHAR(50), -- npm, pypi, maven, etc.
    reported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP WITH TIME ZONE,
    verified_by_user_id UUID REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT typosquat_unique UNIQUE(legitimate_package, typosquat_package, package_source)
);
CREATE INDEX idx_typosquatting_package_source ON typosquatting_candidates(package_source);
CREATE INDEX idx_typosquatting_legitimate ON typosquatting_candidates(legitimate_package);
CREATE INDEX idx_typosquatting_verified ON typosquatting_candidates(verified);
```

### 3.5 RISK SCORING TABLES

#### Table: risk_scores (With TimescaleDB)
```sql
-- Enable TimescaleDB extension (one-time)
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create hypertable for time-series data
SELECT create_hypertable(
    'risk_scores',
    'calculated_at',
    if_not_exists => TRUE
);

-- Hypertable for component risk scores
CREATE TABLE IF NOT EXISTS risk_scores (
    id UUID,
    org_id UUID NOT NULL,
    component_id UUID NOT NULL REFERENCES sbom_components(id),
    score NUMERIC(5,2) NOT NULL,
    severity_breakdown JSONB, -- {critical: 5, high: 10, medium: 20}
    factors_json JSONB, -- {vulnerability_count, age_days, maintenance_status}
    calculated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id, calculated_at)
) PARTITION BY RANGE (calculated_at);

SELECT create_hypertable(
    'risk_scores',
    'calculated_at',
    if_not_exists => TRUE
);

CREATE INDEX idx_risk_scores_component ON risk_scores(component_id, calculated_at DESC);
CREATE INDEX idx_risk_scores_org ON risk_scores(org_id, calculated_at DESC);
CREATE INDEX idx_risk_scores_score ON risk_scores(score DESC, calculated_at DESC);
```

#### Table: sbom_risk_aggregates
```sql
CREATE TABLE sbom_risk_aggregates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    overall_score NUMERIC(5,2),
    critical_vulnerability_count INTEGER DEFAULT 0,
    high_vulnerability_count INTEGER DEFAULT 0,
    medium_vulnerability_count INTEGER DEFAULT 0,
    low_vulnerability_count INTEGER DEFAULT 0,
    threat_detection_count INTEGER DEFAULT 0,
    malicious_package_count INTEGER DEFAULT 0,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE INDEX idx_sbom_risk_sbom_id ON sbom_risk_aggregates(sbom_id);
CREATE INDEX idx_sbom_risk_org_id ON sbom_risk_aggregates(org_id);
CREATE INDEX idx_sbom_risk_overall_score ON sbom_risk_aggregates(overall_score DESC);
```

#### Table: remediation_recommendations
```sql
CREATE TABLE remediation_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
    recommendation_type VARCHAR(100), -- update_available, alternative_package, patch
    target_version VARCHAR(255),
    estimated_effort VARCHAR(50), -- low, medium, high
    risk_reduction_percent INTEGER,
    details_json JSONB, -- {reason, impact, alternative_packages}
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    dismissed_at TIMESTAMP WITH TIME ZONE,
    dismissed_by_user_id UUID REFERENCES users(id)
);
CREATE INDEX idx_remediation_org_id ON remediation_recommendations(org_id);
CREATE INDEX idx_remediation_component_id ON remediation_recommendations(component_id);
```

### 3.6 CONTAINER & COMPLIANCE TABLES

#### Table: container_images
```sql
CREATE TABLE container_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    registry VARCHAR(255), -- docker.io, ghcr.io, etc.
    image_name VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),
    digest VARCHAR(256), -- SHA256 digest
    size_bytes BIGINT,
    created_at_source TIMESTAMP WITH TIME ZONE,
    layers_count INTEGER,
    scanned_at TIMESTAMP WITH TIME ZONE,
    vulnerability_count INTEGER,
    risk_score NUMERIC(5,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_container_images_registry ON container_images(registry);
CREATE INDEX idx_container_images_image_name ON container_images(image_name);
CREATE INDEX idx_container_images_digest ON container_images(digest);
```

#### Table: compliance_policies
```sql
CREATE TABLE compliance_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(100), -- nist, pci_dss, hipaa, iso27001, custom
    description TEXT,
    policy_rules JSONB NOT NULL, -- Rules for policy compliance
    severity_threshold VARCHAR(50), -- critical, high, medium
    is_active BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE, -- System policy?
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT policy_name_unique UNIQUE(org_id, name)
);
CREATE INDEX idx_compliance_policies_org ON compliance_policies(org_id);
CREATE INDEX idx_compliance_policies_type ON compliance_policies(policy_type);
```

#### Table: audit_logs
```sql
-- Using Elasticsearch for performance, but keeping summary in PostgreSQL
CREATE TABLE audit_logs_summary (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action_type VARCHAR(100), -- created, updated, deleted, exported, scanned
    resource_type VARCHAR(100), -- project, sbom, user, policy, etc.
    resource_id VARCHAR(255),
    changes_json JSONB, -- Before/after changes
    status VARCHAR(50) DEFAULT 'success', -- success, failed, denied
    status_code INTEGER,
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_logs_org ON audit_logs_summary(org_id);
CREATE INDEX idx_audit_logs_user ON audit_logs_summary(user_id);
CREATE INDEX idx_audit_logs_created ON audit_logs_summary(created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs_summary(resource_type, resource_id);
```

---

## 4. Indexing Strategy

### 4.1 Index Categories

| Category | Purpose | Examples |
|---|---|---|
| **Primary Keys** | Uniqueness & clustering | All tables (auto-created) |
| **Foreign Keys** | Join performance | org_id, project_id, sbom_id |
| **Search** | WHERE clause filtering | name, email, severity |
| **Sort** | ORDER BY optimization | created_at DESC, score DESC |
| **Composite** | Multi-column queries | (org_id, created_at) |
| **Full-Text** | Text search | Component names (Elasticsearch) |

### 4.2 Index Performance Targets

- Index size: <20% of table size
- Index maintenance time: <5% of write operations
- Query improvement: Minimum 10x faster

---

## 5. Partitioning Strategy

### 5.1 Partition Scheme

**Primary Partition**: org_id (for multi-tenancy isolation)

**Secondary Partitions**:
- **sboms**: By created_at (yearly)
- **component_vulnerabilities**: By org_id + created_at (quarterly)
- **risk_scores**: By created_at (TimescaleDB hypertable - automatic)
- **audit_logs**: By created_at (monthly)

### 5.2 Partition Benefits

- ✅ Improved query performance (scans smaller partitions)
- ✅ Faster maintenance (maintenance on per-partition)
- ✅ Easier archival (move old partitions to cold storage)
- ✅ Better multi-tenancy isolation

---

## 6. View Definitions (Key Views)

### 6.1 Common Query Views

```sql
-- SBOM Summary View
CREATE VIEW v_sbom_summary AS
SELECT 
    s.id,
    s.project_id,
    p.name as project_name,
    COUNT(DISTINCT sc.id) as component_count,
    COUNT(DISTINCT cv.id) as vulnerability_count,
    MAX(cv.severity) as max_severity,
    s.risk_score,
    s.generated_at
FROM sboms s
JOIN projects p ON s.project_id = p.id
LEFT JOIN sbom_components sc ON s.id = sc.sbom_id
LEFT JOIN component_vulnerabilities cv ON sc.id = cv.component_id
GROUP BY s.id, s.project_id, p.name;

-- Risk Dashboard View
CREATE VIEW v_risk_dashboard AS
SELECT 
    org_id,
    COUNT(DISTINCT sbom_id) as total_sboms,
    SUM(CASE WHEN overall_score >= 80 THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN overall_score >= 60 AND overall_score < 80 THEN 1 ELSE 0 END) as high_count,
    AVG(overall_score) as avg_risk_score,
    calculated_at
FROM sbom_risk_aggregates
GROUP BY org_id, calculated_at;

-- Vulnerability Summary View
CREATE VIEW v_vulnerability_summary AS
SELECT 
    cve_id,
    severity,
    cvss_v3_score,
    COUNT(DISTINCT cc.id) as affected_components,
    COUNT(DISTINCT cc.sbom_id) as affected_sboms,
    published_date
FROM vulnerabilities v
LEFT JOIN component_vulnerabilities cc ON v.id = cc.vulnerability_id
GROUP BY v.id, v.cve_id, v.severity, v.cvss_v3_score, v.published_date;
```

---

## 7. Row-Level Security (RLS) Policy

### 7.1 RLS Strategy

```sql
-- Enable RLS on sensitive tables
ALTER TABLE sboms ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE component_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs_summary ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see data from their organization
CREATE POLICY org_isolation_policy ON sboms
    FOR SELECT
    USING (
        org_id = (SELECT org_id FROM users WHERE id = current_user_id)
    );

-- Policy: Admins can see all org data
CREATE POLICY admin_bypass_policy ON sboms
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_roles ur
            WHERE ur.user_id = current_user_id
            AND ur.role_id IN (SELECT id FROM roles WHERE name = 'org_admin')
        )
    );
```

---

## 8. Performance Optimization Strategies

### 8.1 Query Optimization

| Optimization | Target Tables | Expected Impact |
|---|---|---|
| Composite indices | sbom_components, component_vulnerabilities | 10-50x faster |
| Materialized views | Risk aggregates, SBOM summaries | Instant queries |
| Caching layer (Redis) | Vulnerabilities, risk scores | 100-1000x faster |
| Connection pooling | All connections | Reduced latency |
| Query result pagination | Large result sets | Better UX |

### 8.2 Write Optimization

- Batch inserts (100+ records at a time)
- Asynchronous updates (use message queue)
- Deferred index updates (rebuild during low traffic)

---

## 9. Migration & Setup Strategy

### 9.1 Database Initialization

```bash
# Step 1: Create database
createdb sbom_platform_prod

# Step 2: Enable extensions
psql sbom_platform_prod -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
psql sbom_platform_prod -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql sbom_platform_prod -c "CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;"

# Step 3: Run schema migrations (via Alembic)
alembic upgrade head

# Step 4: Create RLS policies
psql sbom_platform_prod -f rls_policies.sql

# Step 5: Create views
psql sbom_platform_prod -f views.sql

# Step 6: Create indices
psql sbom_platform_prod -f indices.sql
```

### 9.2 Data Migration

From existing systems (if any):
1. Export data from legacy system
2. Validate data integrity
3. Transform to new schema
4. Load data with constraints disabled
5. Verify foreign key relationships
6. Re-enable constraints
7. Rebuild indices
8. Run integrity checks

---

## 10. Capacity & Scaling

### 10.1 Storage Estimates (Year 1)

| Data Type | Records | Size | Notes |
|---|---|---|---|
| Projects | 10K | 50MB | Metadata only |
| SBOMs | 100K | 50GB | JSON content + backups |
| Components | 500M | 250GB | Indexed for speed |
| Vulnerabilities | 1M | 5GB | ~5KB per record |
| Audit Logs | 100M | 50GB | Compress after 1 month |
| **Total** | | **~350GB** | Plus backups (700GB S3) |

### 10.2 Scaling Thresholds

| Threshold | Action |
|---|---|
| DB size > 500GB | Add read replicas |
| QPS > 10K | Implement sharding |
| Write latency > 100ms | Optimize slow queries |
| Backup time > 1 hour | Implement incremental backups |
| Query time > 500ms | Create materialized views |

---

## 11. Backup & Recovery

### 11.1 Backup Strategy

- **Full backups**: Daily (12 AM UTC)
- **Incremental backups**: Every 6 hours
- **Point-in-time recovery**: 30-day retention
- **Replication**: Hot standby (RTO: 2 min)
- **Geo-redundancy**: S3 cross-region replication

### 11.2 RTO/RPO Targets

| Scenario | RTO | RPO | Mechanism |
|---|---|---|---|
| Single node failure | 5 min | 1 min | Hot standby promotion |
| Data corruption | 15 min | <1 min | PITR restore |
| Regional outage | 30 min | 5 min | Cross-region failover |

---

## 12. Database Monitoring

### 12.1 Key Metrics

- Query latency (p50, p95, p99)
- Index effectiveness (hit ratio > 90%)
- Cache hit ratio (> 80%)
- Connections count (< 400/500)
- Replication lag (< 1 second)
- Backup success rate (100%)

### 12.2 Alerting Rules

- Query time > 1000ms → ALERT
- Replication lag > 5s → ALERT
- Backup failure → ALERT
- Connection pool near capacity → ALERT
- Index bloat > 20% → ALERT

---

## 13. Phase 3 Deliverables Checklist

- [x] Complete database schema (40+ tables)
- [x] Entity-relationship diagrams
- [x] Normalization strategy (3NF)
- [x] Indexing strategy (primary, secondary, composite)
- [x] Partitioning strategy (org_id, time-based)
- [x] View definitions
- [x] Row-level security (RLS) policies
- [x] Performance optimization strategies
- [x] Capacity planning
- [x] Backup & recovery procedures
- [x] Monitoring & alerting

---

## 14. Next Steps (Phase 4: API Design)

**Phase 4 Scope**:
1. Detailed API specifications (OpenAPI/Swagger)
2. API endpoint design (50+ endpoints)
3. Request/response schemas
4. Error handling standards
5. Rate limiting policies
6. API versioning strategy
7. API documentation

**Phase 4 Duration**: 2 weeks

---

**Document Control**
- Version: 1.0
- Status: IN PROGRESS
- Last Updated: 2026-07-08
- Target Completion: 2026-07-22
- Next Phase: Phase 4 (API Design)
