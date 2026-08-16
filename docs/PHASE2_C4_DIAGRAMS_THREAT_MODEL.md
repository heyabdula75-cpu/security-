# Phase 2: C4 Architecture Diagrams & Threat Model

**Status**: DRAFT
**Date**: 2026-07-08
**Version**: 1.0

---

## 1. C4 Model Architecture

### 1.1 Context Diagram (Level 1)

```
┌─────────────────────────────────────────────────────────────────┐
│                    External Systems                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│ │ GitHub / Git │  │ Docker       │  │ Container    │          │
│ │ Repositories │  │ Registries   │  │ Registries   │          │
│ └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│        │                 │                  │                   │
│        └─────────┬───────┴──────────┬───────┘                   │
│                  │                  │                           │
│                  ▼                  ▼                           │
│  ┌──────────────────────────────────────────┐                 │
│  │   AI Supply Chain Security Platform     │                 │
│  │   (Webhooks, API calls, scanning)       │                 │
│  │                                          │                 │
│  │  ┌─────────────────────────────────┐   │                 │
│  │  │  REST APIs                       │   │                 │
│  │  │  - SBOM Management               │   │                 │
│  │  │  - Vulnerability Scanning        │   │                 │
│  │  │  - Threat Detection              │   │                 │
│  │  │  - Risk Scoring                  │   │                 │
│  │  └─────────────────────────────────┘   │                 │
│  │                                          │                 │
│  │  ┌─────────────────────────────────┐   │                 │
│  │  │  Web UI / Dashboards             │   │                 │
│  │  │  - Executive Dashboard           │   │                 │
│  │  │  - Developer Dashboard           │   │                 │
│  │  │  - Security Dashboard            │   │                 │
│  │  └─────────────────────────────────┘   │                 │
│  │                                          │                 │
│  └──────────────────────────────────────────┘                 │
│                  ▲                                             │
│                  │                                             │
├──────────────────┼─────────────────────────────────────────────┤
│                  │                                             │
│  External APIs   │                                             │
│  ┌──────────────┴───────────┐                                 │
│  │ Threat Intelligence      │                                 │
│  │ - NVD                    │                                 │
│  │ - GitHub Advisories      │                                 │
│  │ - OSV                    │                                 │
│  │ - Malware feeds          │                                 │
│  └──────────────────────────┘                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    End Users                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│ │ Security     │  │ Developers   │  │ Compliance   │          │
│ │ Team         │  │              │  │ Officers     │          │
│ └──────────────┘  └──────────────┘  └──────────────┘          │
│         │               │                  │                   │
│         └───────────┬───┴──────────┬───────┘                   │
│                     │              │                           │
│                     ▼              ▼                           │
│          ┌──────────────────────────┐                         │
│          │  Web Browser / CLI       │                         │
│          │  - Access Dashboards     │                         │
│          │  - Query APIs            │                         │
│          │  - Generate Reports      │                         │
│          └──────────────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Container Diagram (Level 2)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  AI Supply Chain Security Platform                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  User Interface Container                   │   │
│  │  ┌──────────────────────────────────────────────────────┐ │   │
│  │  │  React/TypeScript Web Application                   │ │   │
│  │  │  - Executive Dashboard                             │ │   │
│  │  │  - Developer Dashboard                             │ │   │
│  │  │  - Security Dashboard                              │ │   │
│  │  │  - SBOM Management                                 │ │   │
│  │  │  - Vulnerability Viewer                            │ │   │
│  │  │  - Risk Analysis                                   │ │   │
│  │  │  - Report Generation                               │ │   │
│  │  │                                                     │ │   │
│  │  │  Technology: React 18, TypeScript, Tailwind CSS   │ │   │
│  │  │  State Management: Zustand                         │ │   │
│  │  │  HTTP Client: React Query                          │ │   │
│  │  └──────────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────────┘   │
│         │                                                          │
│         │ HTTPS / REST                                            │
│         ▼                                                          │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                 API Container                              │   │
│  │  ┌──────────────────────────────────────────────────────┐ │   │
│  │  │  API Gateway (Kong / FastAPI)                       │ │   │
│  │  │  - Request routing                                  │ │   │
│  │  │  - Authentication                                   │ │   │
│  │  │  - Rate limiting                                    │ │   │
│  │  │  - Response transformation                          │ │   │
│  │  └──────────────────────────────────────────────────────┘ │   │
│  │         │                                                  │   │
│  │         ├──→ SBOM Service        (FastAPI)               │   │
│  │         ├──→ Vulnerability Svc   (FastAPI)               │   │
│  │         ├──→ Threat Detection    (FastAPI + Celery)     │   │
│  │         ├──→ Risk Scoring        (FastAPI)               │   │
│  │         ├──→ Container Service   (FastAPI + Trivy)      │   │
│  │         ├──→ Compliance Service  (FastAPI)               │   │
│  │         ├──→ Auth Service        (FastAPI)               │   │
│  │         └──→ Analytics Service   (FastAPI)               │   │
│  │                                                             │   │
│  │  Technology: FastAPI, Python 3.11+, Pydantic             │   │
│  └────────────────────────────────────────────────────────────┘   │
│         │                                                          │
│         ├─────────────────┬──────────────────┬─────────────┐      │
│         │                 │                  │             │      │
│         ▼                 ▼                  ▼             ▼      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ ┌──────┐  │
│  │  Database    │  │ Cache Layer  │  │  Message     │ │ File │  │
│  │  Container   │  │  Container   │  │  Queue       │ │Storag│  │
│  │              │  │              │  │  Container   │ │      │  │
│  │ PostgreSQL   │  │ Redis        │  │              │ │  S3  │  │
│  │ + TimescaleDB│  │ Cluster      │  │ RabbitMQ     │ └──────┘  │
│  │              │  │              │  │              │            │
│  │ 40+ tables   │  │ Session store│  │ Async tasks  │            │
│  │ Vulnerabilities     │ Hot data    │  │ Event streaming           │
│  │ SBOMs        │  │ Caching      │  │              │            │
│  │ Audit logs   │  │              │  │              │            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Elasticsearch Container                      │   │
│  │  - Audit logs                                            │   │
│  │  - Full-text search (SBOM, vulnerability search)        │   │
│  │  - Alerting logs                                         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Worker Container (Celery)                   │   │
│  │  - SBOM generation                                      │   │
│  │  - Threat intelligence updates                          │   │
│  │  - Container image scanning                             │   │
│  │  - Report generation                                    │   │
│  │  - Webhook distribution                                 │   │
│  │                                                           │   │
│  │  Scaling: Min 5, Max 50 pods                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Component Diagram (Level 3: API Container)

```
┌─────────────────────────────────────────────────────────────────┐
│                   FastAPI Application Container                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ROUTE LAYER                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Request Router (FastAPI)                                │   │
│  │ ├─ /api/v1/sboms → SBOM Controller                      │   │
│  │ ├─ /api/v1/vulnerabilities → Vulnerability Controller  │   │
│  │ ├─ /api/v1/threats → Threat Controller                 │   │
│  │ ├─ /api/v1/risks → Risk Controller                     │   │
│  │ ├─ /api/v1/containers → Container Controller           │   │
│  │ ├─ /api/v1/compliance → Compliance Controller          │   │
│  │ ├─ /api/v1/auth → Auth Controller                      │   │
│  │ └─ /api/v1/analytics → Analytics Controller            │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│  MIDDLEWARE LAYER       │                                       │
│  ┌──────────────────────┴──────────────────────────────────┐   │
│  │ Authentication Middleware (JWT/API Key)               │   │
│  │ Authorization Middleware (RBAC)                        │   │
│  │ Request Validation Middleware                          │   │
│  │ Rate Limiting Middleware                               │   │
│  │ Logging Middleware                                     │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│  BUSINESS LOGIC LAYER   │                                       │
│  ┌──────────────────────┴──────────────────────────────────┐   │
│  │                                                          │   │
│  │ ┌──────────────────┐  ┌──────────────────┐             │   │
│  │ │ SBOM Service     │  │ Vulnerability    │             │   │
│  │ │ - Generate       │  │ Service          │             │   │
│  │ │ - Parse/Validate │  │ - Scan           │             │   │
│  │ │ - Store          │  │ - Query          │             │   │
│  │ │ - Export         │  │ - Update feeds   │             │   │
│  │ └──────────────────┘  └──────────────────┘             │   │
│  │                                                          │   │
│  │ ┌──────────────────┐  ┌──────────────────┐             │   │
│  │ │ Threat Service   │  │ Risk Service     │             │   │
│  │ │ - Detect         │  │ - Calculate      │             │   │
│  │ │ - Classify       │  │ - Analyze        │             │   │
│  │ │ - Alert          │  │ - Recommend      │             │   │
│  │ └──────────────────┘  └──────────────────┘             │   │
│  │                                                          │   │
│  │ ┌──────────────────┐  ┌──────────────────┐             │   │
│  │ │ Container Svc    │  │ Compliance Svc   │             │   │
│  │ │ - Scan images    │  │ - Generate       │             │   │
│  │ │ - Verify         │  │ - Enforce policy │             │   │
│  │ │ - Registry mgmt  │  │ - Audit logs     │             │   │
│  │ └──────────────────┘  └──────────────────┘             │   │
│  │                                                          │   │
│  │ ┌──────────────────┐  ┌──────────────────┐             │   │
│  │ │ Auth Service     │  │ Analytics Svc    │             │   │
│  │ │ - Authenticate   │  │ - Track metrics  │             │   │
│  │ │ - Authorize      │  │ - Generate stats │             │   │
│  │ │ - Manage users   │  │ - Create trends  │             │   │
│  │ └──────────────────┘  └──────────────────┘             │   │
│  │                                                          │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│  DATA ACCESS LAYER      │                                       │
│  ┌──────────────────────┴──────────────────────────────────┐   │
│  │                                                          │   │
│  │  ┌──────────────────────────────────────────────────┐   │   │
│  │  │ ORM Layer (SQLAlchemy)                          │   │   │
│  │  │ - Query building                                │   │   │
│  │  │ - Object mapping                                │   │   │
│  │  │ - Relationship management                       │   │   │
│  │  └──────────┬───────────────────────────────────────┘   │   │
│  │             │                                            │   │
│  │  ┌──────────┴────────────────────────────────────────┐   │   │
│  │  │ Repository Pattern Implementation                │   │   │
│  │  │ - Database queries                               │   │   │
│  │  │ - Cache operations                               │   │   │
│  │  │ - Transaction management                         │   │   │
│  │  └──────────────────────────────────────────────────┘   │   │
│  │                                                          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
        │                │                │                    
        ▼                ▼                ▼                    
   ┌─────────┐     ┌──────────┐     ┌──────────┐              
   │PostgreSQL    │ Redis     │     │RabbitMQ  │              
   │+ TimescaleDB │ Cache     │     │ Message  │              
   └─────────┘     └──────────┘     │ Queue    │              
                                     └──────────┘              
```

---

## 2. Detailed Threat Model (STRIDE Analysis)

### 2.1 Threat Model Scope

**Asset**: Customer SBOM data, vulnerability data, audit logs
**Entry Points**: REST APIs, Web UI, Webhooks
**Trust Boundaries**: 
- Between client and platform
- Between services (API gateway → microservices)
- Between platform and data stores
- Between platform and external systems

### 2.2 STRIDE Analysis

#### 2.2.1 Spoofing (Identity)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **API Impersonation** | Attacker impersonates valid user via stolen credentials | High | MFA, secure password policy, session timeouts |
| **API Key Theft** | Attacker steals API key and uses it | High | API key rotation, short expiration, secure storage |
| **Service-to-Service** | Attacker spoofs one service to another | Medium | mTLS between services, mutual authentication |
| **Webhook Spoofing** | Attacker sends fake webhook to trigger actions | Medium | Webhook signature verification, IP whitelisting |

#### 2.2.2 Tampering (Data Integrity)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **SBOM Modification** | Attacker modifies stored SBOM data | Critical | SBOM signatures, integrity hashes, audit logs |
| **Vulnerability Data** | Attacker modifies vulnerability records | Critical | Signed vulnerability feeds, immutable logs |
| **Audit Log Tampering** | Attacker modifies audit logs to cover tracks | Critical | Append-only logs, log signing, centralized logging |
| **Database Injection** | Attacker modifies data via SQL injection | High | Parameterized queries, input validation |
| **API Response Tampering** | Attacker modifies API responses in transit | Medium | HTTPS/TLS enforcement, response signing |

#### 2.2.3 Repudiation (Accountability)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **Action Denial** | User denies performing an action | Medium | Comprehensive audit logging, timestamps |
| **Report Manipulation** | User denies generating/sending report | Medium | Report signatures, generation logs |
| **Scan Denial** | User denies initiating scan | Low | Scan logs with user ID, timestamp |

#### 2.2.4 Information Disclosure (Confidentiality)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **SBOM Exposure** | Unauthorized access to customer SBOM | Critical | RBAC, encryption, row-level security |
| **Vulnerability Disclosure** | Premature disclosure of 0-day | High | Embargo policies, access controls |
| **API Key Exposure** | API key visible in logs/responses | High | Never log keys, use masking |
| **PII Leakage** | User data exposed (emails, IPs) | High | Data encryption, PII detection/masking |
| **Cache Poisoning** | Attacker poisons cached data | Medium | Cache integrity checks, TTL limits |
| **Side-Channel Attack** | Information leaked via timing/resource usage | Low | Constant-time operations, rate limiting |

#### 2.2.5 Denial of Service (Availability)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **API DDoS** | Attacker floods API with requests | High | Rate limiting, WAF, DDoS service |
| **Resource Exhaustion** | Attacker exhausts memory/CPU | High | Resource limits per user, queue limits |
| **Database Overload** | Attacker triggers expensive queries | High | Query timeout, complexity limits, caching |
| **Malicious Scan** | Attacker submits massive artifact to scan | Medium | File size limits, scan timeout |
| **Queue Flooding** | Attacker floods message queue | Medium | Queue depth limits, consumer limits |

#### 2.2.6 Elevation of Privilege (Authorization)

| Threat | Description | Severity | Mitigation |
|---|---|---|---|
| **RBAC Bypass** | Attacker bypasses role checks | Critical | Policy enforcement at every layer, principle of least privilege |
| **Privilege Escalation** | User escalates own privileges | Critical | Admin approval required, dual controls, audit |
| **Cross-Org Access** | Attacker accesses another org's data | Critical | Org_id validation on every query, RLS policies |
| **Service Impersonation** | Attacker calls service as admin | High | Service authentication, service-to-service RBAC |

---

### 2.3 Attack Scenarios & Responses

**Scenario 1: Attacker Steals SBOM Data**
- Vector: API key theft or session hijacking
- Impact: Competitor gains access to customer dependencies
- Detection: Unusual query patterns, access from new IP
- Response: Immediate account lockout, password reset, key rotation

**Scenario 2: Supply Chain Attack on Platform**
- Vector: Malicious dependency in platform code
- Impact: Platform compromised, data at risk
- Detection: Dependency scanning, code review, supply chain verification
- Response: Immediate incident response, customer notification

**Scenario 3: Attacker Modifies Audit Logs**
- Vector: Compromised database access or admin account
- Impact: Cover tracks, hide malicious activities
- Detection: Log integrity checking, centralized immutable logging
- Response: Forensic analysis, breach investigation

---

## 3. Network Architecture

### 3.1 Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet (Public)                        │
└────────────────┬────────────────────────────────────────────┘
                 │
          ┌──────▼──────┐
          │ Cloudflare  │ (DDoS Protection, WAF, CDN)
          └──────┬──────┘
                 │
          ┌──────▼──────────┐
          │ AWS ALB / NLB   │ (Load Balancer, TLS Termination)
          └──────┬──────────┘
                 │
          ┌──────▼──────────────────────────┐
          │ Kubernetes Ingress              │
          │ ├─ External Ingress (APIs)      │
          │ ├─ Internal Ingress (services)  │
          └──────┬─────────────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
  ┌────┐     ┌─────────┐  ┌─────────┐
  │API │     │Frontend │  │Workers  │
  │Pods│     │Pods     │  │Pods     │
  └────┘     └─────────┘  └─────────┘
    │            │            │
    └────────────┼────────────┘
                 │
          ┌──────▼──────────────────────────┐
          │ Kubernetes Network Policies     │
          │ (Ingress/Egress rules)          │
          └──────┬───────────────────────────┘
                 │
    ┌────────────┼────────────────────────┐
    │            │                        │
    ▼            ▼                        ▼
┌────────┐  ┌─────────────┐     ┌─────────────┐
│Data    │  │Cache/Queue  │     │Elasticsearch│
│Network │  │Network      │     │Network      │
│- Pods  │  │- Pods       │     │- Pods       │
│connect │  │- Isolated   │     │- Isolated   │
│directly│  │             │     │             │
└────────┘  └─────────────┘     └─────────────┘
```

### 3.2 Network Policies

**Ingress Rules (Allow)**:
- External → Ingress Controller (port 443, 80)
- Ingress Controller → API Pods (port 8000)
- API Pods → Frontend (port 3000)

**Egress Rules (Allow)**:
- API Pods → PostgreSQL Pods (port 5432)
- API Pods → Redis Pods (port 6379)
- API Pods → RabbitMQ Pods (port 5672)
- API Pods → External APIs (port 443 only)
- Workers → S3 (port 443)

---

## 4. Security Considerations by Component

### 4.1 API Gateway Security

- **TLS 1.3**: Enforce minimum TLS version
- **Rate Limiting**: 100 req/sec per IP, 1000 req/sec per user
- **WAF Rules**: Block common attack patterns (SQL injection, XSS)
- **Request Validation**: Validate content-type, size, format
- **CORS**: Strict origin whitelist

### 4.2 Service-to-Service Security

- **mTLS**: Mutual TLS certificates for all service communication
- **Service Mesh**: Istio for advanced traffic management
- **Network Policies**: Deny-all, allow specific pods
- **Service Accounts**: Each service has unique service account
- **RBAC**: Services only get needed permissions

### 4.3 Database Security

- **Connection Encryption**: SSL mode=require
- **Row-Level Security**: Users see only own org data
- **Field Encryption**: Sensitive columns encrypted (password hashes, keys)
- **Audit Logging**: All modifications logged
- **Least Privilege**: Application user has minimal permissions

### 4.4 External Integration Security

- **API Authentication**: OAuth2, API keys, mTLS
- **Data Validation**: Validate all external data before processing
- **Rate Limiting**: Respect API rate limits
- **Timeout**: Aggressive timeouts for external calls
- **Retry Logic**: Exponential backoff with jitter

---

## 5. Phase 2 Deliverables Summary

- [x] High-level system architecture
- [x] Microservices component design
- [x] C4 architecture diagrams
- [x] Threat model (STRIDE analysis)
- [x] Network architecture
- [x] Security architecture details
- [x] Performance strategy
- [x] Scalability design

---

**Document Control**
- Version: 1.0
- Status: DRAFT
- Last Updated: 2026-07-08
- Next Phase: Phase 3 (Database Design)
