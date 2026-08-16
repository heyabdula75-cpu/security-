# Phase 4: API Specification
## AI Supply Chain Security & SBOM Verification Platform

**Status**: IN PROGRESS
**Date**: 2026-07-08
**Version**: 1.0

---

## 1. API Design Principles

### 1.1 REST API Standards

1. **Resource-Oriented**: Resources represented as nouns (projects, sboms, components)
2. **HTTP Verbs**: Standard CRUD operations (GET, POST, PUT, DELETE, PATCH)
3. **Stateless**: Each request contains all needed context
4. **Versioning**: All endpoints prefixed with /api/v1 (allow v2+ in future)
5. **Content Negotiation**: Accept JSON requests/responses
6. **Caching**: Proper Cache-Control headers
7. **Pagination**: Standardized limit/offset for large datasets
8. **Filtering**: Query parameters for filtering
9. **Sorting**: Support sort by multiple fields
10. **Documentation**: Every endpoint documented with OpenAPI

### 1.2 API Architecture

```
Client (Web/Mobile/CLI)
    ↓
[TLS/HTTPS - Port 443]
    ↓
API Gateway (Kong/FastAPI)
├─ Rate Limiting
├─ Authentication (JWT/API Key)
├─ Request Validation
└─ Response Transformation
    ↓
[Service Mesh - mTLS]
    ↓
Microservices (8 services)
├─ SBOM Service
├─ Vulnerability Service
├─ Threat Service
├─ Risk Service
├─ Container Service
├─ Compliance Service
├─ Auth Service
└─ Analytics Service
```

---

## 2. Global API Standards

### 2.1 Request/Response Format

**Standard Success Response (200, 201)**:
```json
{
  "success": true,
  "data": { /* resource data */ },
  "meta": {
    "timestamp": "2026-07-08T10:30:00Z",
    "request_id": "req_abc123xyz",
    "version": "1.0"
  }
}
```

**Paginated Response**:
```json
{
  "success": true,
  "data": [{ /* items */ }],
  "pagination": {
    "total": 1000,
    "limit": 20,
    "offset": 0,
    "has_more": true
  },
  "meta": { /* ... */ }
}
```

**Error Response (4xx, 5xx)**:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": [
      {
        "field": "email",
        "issue": "Invalid format"
      }
    ],
    "request_id": "req_abc123xyz"
  }
}
```

### 2.2 HTTP Status Codes

| Status | Usage |
|---|---|
| **200 OK** | Successful GET, PUT, PATCH |
| **201 Created** | Successful POST creating resource |
| **204 No Content** | Successful DELETE |
| **400 Bad Request** | Invalid input, validation error |
| **401 Unauthorized** | Missing/invalid authentication |
| **403 Forbidden** | Authenticated but not authorized |
| **404 Not Found** | Resource not found |
| **409 Conflict** | Resource conflict (duplicate key) |
| **429 Too Many Requests** | Rate limit exceeded |
| **500 Internal Server Error** | Server error |
| **503 Service Unavailable** | Service temporarily down |

### 2.3 Authentication

**Header Format**:
```
Authorization: Bearer <JWT_TOKEN>
```

**OR (for API keys)**:
```
Authorization: ApiKey <API_KEY>
```

**Token Claims (JWT)**:
```json
{
  "sub": "user_id_uuid",
  "org": "org_id_uuid",
  "roles": ["admin", "developer"],
  "iat": 1657264200,
  "exp": 1657350600,
  "iss": "https://api.sbom.io"
}
```

### 2.4 Rate Limiting

**Rate Limit Headers**:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1657264200
```

**Limits**:
- **Authenticated User**: 1000 requests/minute
- **API Key**: Per-key quota (configurable)
- **IP Address**: 100 requests/minute (unauthenticated)
- **Burst**: Allow 20% overage for 10 seconds

### 2.5 Pagination Standards

**Query Parameters**:
```
GET /api/v1/sboms?limit=20&offset=0&sort=-created_at&filter=status:active
```

**Default Limits**:
- Default: limit=20
- Maximum: limit=100
- Minimum: limit=1

**Sorting**:
- Prefix with `-` for descending (e.g., `-created_at`)
- Comma-separated for multiple fields (e.g., `status,-created_at`)

---

## 3. Authentication Service APIs

### 3.1 User Management Endpoints

#### POST /api/v1/auth/register
**Description**: Register new user account
**Authentication**: None
**Request**:
```json
{
  "email": "user@company.com",
  "password": "SecurePass123!",
  "full_name": "John Doe",
  "organization_name": "ACME Corp"
}
```
**Response (201)**:
```json
{
  "success": true,
  "data": {
    "user_id": "user_uuid",
    "email": "user@company.com",
    "organization_id": "org_uuid",
    "verification_required": true,
    "verification_sent_to": "user@company.com"
  }
}
```
**Errors**: 400 (validation), 409 (email exists)

#### POST /api/v1/auth/login
**Description**: Authenticate user and return JWT token
**Authentication**: None
**Request**:
```json
{
  "email": "user@company.com",
  "password": "SecurePass123!"
}
```
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "access_token": "jwt_token_here",
    "refresh_token": "refresh_token_here",
    "expires_in": 3600,
    "user": {
      "id": "user_uuid",
      "email": "user@company.com",
      "roles": ["admin"]
    }
  }
}
```
**Errors**: 401 (invalid credentials), 429 (too many attempts)

#### POST /api/v1/auth/refresh-token
**Description**: Refresh expired access token
**Authentication**: Refresh token required
**Request**:
```json
{
  "refresh_token": "refresh_token_here"
}
```
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "access_token": "new_jwt_token",
    "expires_in": 3600
  }
}
```

#### POST /api/v1/auth/logout
**Description**: Invalidate access token
**Authentication**: Bearer token
**Response (204)**: No content

#### GET /api/v1/auth/profile
**Description**: Get current user profile
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "user_uuid",
    "email": "user@company.com",
    "full_name": "John Doe",
    "organization_id": "org_uuid",
    "roles": ["admin"],
    "mfa_enabled": true,
    "created_at": "2026-01-01T00:00:00Z",
    "last_login": "2026-07-08T10:30:00Z"
  }
}
```

#### POST /api/v1/auth/mfa/enable
**Description**: Enable MFA on account
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "qr_code": "data:image/png;base64,...",
    "secret": "JBSWY3DPEBLW64TMMQ======",
    "backup_codes": ["code1", "code2", "..."]
  }
}
```

#### POST /api/v1/auth/mfa/verify
**Description**: Verify MFA code and enable MFA
**Authentication**: Bearer token
**Request**:
```json
{
  "code": "123456"
}
```
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "mfa_enabled": true
  }
}
```

---

## 4. SBOM Service APIs

### 4.1 SBOM Endpoints

#### POST /api/v1/sboms/generate
**Description**: Generate SBOM from project
**Authentication**: Bearer token (Developer role+)
**Request**:
```json
{
  "project_id": "project_uuid",
  "source": "github",
  "repository_url": "https://github.com/owner/repo",
  "branch": "main",
  "format": "cyclonedx-json"
}
```
**Response (202 Accepted)**: Returns job_id for async processing
```json
{
  "success": true,
  "data": {
    "job_id": "job_uuid",
    "status": "processing",
    "estimated_completion": "2026-07-08T10:35:00Z"
  }
}
```

#### GET /api/v1/sboms/generate/{job_id}
**Description**: Check SBOM generation status
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "job_id": "job_uuid",
    "status": "completed",
    "sbom_id": "sbom_uuid",
    "completed_at": "2026-07-08T10:33:00Z"
  }
}
```

#### GET /api/v1/sboms
**Description**: List SBOMs for organization
**Authentication**: Bearer token
**Query Parameters**:
- `project_id` (optional): Filter by project
- `limit` (default: 20): Items per page
- `offset` (default: 0): Pagination offset
- `sort` (default: -created_at): Sort field
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "sbom_uuid",
      "project_id": "project_uuid",
      "format": "cyclonedx-json",
      "component_count": 145,
      "vulnerability_count": 3,
      "risk_score": 45.2,
      "generated_at": "2026-07-08T10:00:00Z",
      "created_at": "2026-07-08T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 50,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

#### GET /api/v1/sboms/{sbom_id}
**Description**: Get specific SBOM
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "sbom_uuid",
    "project_id": "project_uuid",
    "format": "cyclonedx-json",
    "version": "1.5",
    "content": { /* Full SBOM JSON */ },
    "component_count": 145,
    "vulnerability_count": 3,
    "risk_score": 45.2,
    "generated_by": "syft",
    "generated_at": "2026-07-08T10:00:00Z"
  }
}
```

#### GET /api/v1/sboms/{sbom_id}/export
**Description**: Export SBOM in specified format
**Authentication**: Bearer token
**Query Parameters**:
- `format`: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-yaml (default: cyclonedx-json)
**Response (200)**: File download (Content-Type: application/json or application/xml)

#### DELETE /api/v1/sboms/{sbom_id}
**Description**: Delete SBOM
**Authentication**: Bearer token (Admin role+)
**Response (204)**: No content

### 4.2 Component Endpoints

#### GET /api/v1/components
**Description**: List components
**Authentication**: Bearer token
**Query Parameters**:
- `sbom_id` (required): Filter by SBOM
- `search` (optional): Search by name
- `limit`, `offset`, `sort`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "component_uuid",
      "name": "express",
      "version": "4.18.2",
      "type": "library",
      "purl": "pkg:npm/express@4.18.2",
      "license": "MIT",
      "author": "TJ Holowaychuk",
      "vulnerability_count": 0,
      "risk_score": 12.5,
      "created_at": "2026-07-08T10:00:00Z"
    }
  ],
  "pagination": { /* ... */ }
}
```

#### GET /api/v1/components/{component_id}
**Description**: Get component details
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "component_uuid",
    "name": "express",
    "version": "4.18.2",
    "type": "library",
    "purl": "pkg:npm/express@4.18.2",
    "license": "MIT",
    "author": "TJ Holowaychuk",
    "homepage_url": "https://expressjs.com",
    "repository_url": "https://github.com/expressjs/express",
    "hash_algorithm": "sha256",
    "hash_value": "abc123...",
    "vulnerabilities": [
      {
        "cve_id": "CVE-2021-1234",
        "severity": "high",
        "description": "Vulnerability description"
      }
    ],
    "risk_score": 12.5
  }
}
```

#### GET /api/v1/components/search
**Description**: Full-text search components
**Authentication**: Bearer token
**Query Parameters**:
- `q` (required): Search query
- `type` (optional): Filter by component type
- `limit`, `offset`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    { /* Component results */ }
  ],
  "pagination": { /* ... */ }
}
```

---

## 5. Vulnerability Service APIs

### 5.1 Vulnerability Endpoints

#### GET /api/v1/vulnerabilities
**Description**: List vulnerabilities
**Authentication**: Bearer token
**Query Parameters**:
- `severity` (optional): critical, high, medium, low
- `component_id` (optional): Filter by component
- `limit`, `offset`, `sort`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "vuln_uuid",
      "cve_id": "CVE-2021-1234",
      "severity": "high",
      "cvss_score": 7.5,
      "epss_score": 0.45,
      "description": "Vulnerability description",
      "published_date": "2021-01-15",
      "affected_packages": [
        {
          "name": "express",
          "version_range": "<4.17.1"
        }
      ],
      "is_exploited": true
    }
  ],
  "pagination": { /* ... */ }
}
```

#### GET /api/v1/vulnerabilities/{vulnerability_id}
**Description**: Get vulnerability details
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "vuln_uuid",
    "cve_id": "CVE-2021-1234",
    "severity": "high",
    "cvss_v3_score": 7.5,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "epss_score": 0.45,
    "cwe_ids": ["CWE-22", "CWE-23"],
    "description": "Full description",
    "published_date": "2021-01-15",
    "last_updated": "2026-07-08",
    "is_exploited": true,
    "exploit_public": true,
    "affected_packages": [
      {
        "name": "express",
        "version_range": "<4.17.1",
        "affected_count": 1234
      }
    ],
    "references": [
      {
        "type": "advisory",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"
      }
    ]
  }
}
```

#### POST /api/v1/vulnerabilities/scan
**Description**: Scan project for vulnerabilities
**Authentication**: Bearer token
**Request**:
```json
{
  "sbom_id": "sbom_uuid",
  "deep_scan": true
}
```
**Response (202 Accepted)**:
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_uuid",
    "status": "processing",
    "estimated_completion": "2026-07-08T10:35:00Z"
  }
}
```

#### GET /api/v1/vulnerabilities/scan/{scan_id}
**Description**: Get scan status
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_uuid",
    "status": "completed",
    "vulnerabilities_found": 3,
    "critical_count": 0,
    "high_count": 2,
    "medium_count": 1,
    "completed_at": "2026-07-08T10:33:00Z"
  }
}
```

---

## 6. Threat Detection Service APIs

### 6.1 Threat Endpoints

#### GET /api/v1/threats
**Description**: List detected threats
**Authentication**: Bearer token
**Query Parameters**:
- `threat_type` (optional): typosquatting, malicious, dependency_confusion
- `severity` (optional): critical, high, medium, low
- `status` (optional): open, confirmed, false_positive
- `limit`, `offset`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "threat_uuid",
      "component_id": "component_uuid",
      "threat_type": "typosquatting",
      "severity": "high",
      "confidence_score": 0.95,
      "description": "Package name similar to popular package",
      "indicators": [
        "Similar package name (Levenshtein distance: 1)",
        "No maintenance history"
      ],
      "detected_at": "2026-07-08T10:00:00Z",
      "status": "open"
    }
  ],
  "pagination": { /* ... */ }
}
```

#### GET /api/v1/threats/{threat_id}
**Description**: Get threat details
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "threat_uuid",
    "component_id": "component_uuid",
    "threat_type": "typosquatting",
    "severity": "high",
    "confidence_score": 0.95,
    "description": "Detailed description",
    "indicators": [ /* ... */ ],
    "detected_at": "2026-07-08T10:00:00Z",
    "status": "open",
    "verified": false,
    "resolved_at": null,
    "resolution_notes": null
  }
}
```

#### POST /api/v1/threats/detect
**Description**: Scan for threats
**Authentication**: Bearer token
**Request**:
```json
{
  "sbom_id": "sbom_uuid",
  "threat_types": ["typosquatting", "malicious", "dependency_confusion"]
}
```
**Response (202 Accepted)**:
```json
{
  "success": true,
  "data": {
    "detection_id": "detection_uuid",
    "status": "processing"
  }
}
```

#### PATCH /api/v1/threats/{threat_id}
**Description**: Update threat status
**Authentication**: Bearer token (Security role+)
**Request**:
```json
{
  "status": "confirmed",
  "verified": true,
  "resolution_notes": "Confirmed as typosquatting attack"
}
```
**Response (200)**: Updated threat object

---

## 7. Risk Scoring Service APIs

### 7.1 Risk Endpoints

#### GET /api/v1/risks/scores
**Description**: Get risk scores
**Authentication**: Bearer token
**Query Parameters**:
- `component_id` (optional)
- `sbom_id` (optional)
- `limit`, `offset`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "risk_uuid",
      "component_id": "component_uuid",
      "score": 65.2,
      "severity_breakdown": {
        "critical": 0,
        "high": 2,
        "medium": 3,
        "low": 1
      },
      "factors": {
        "vulnerability_count": 6,
        "component_age_days": 365,
        "maintenance_status": "active",
        "transitive_dependencies": 25
      },
      "calculated_at": "2026-07-08T10:00:00Z"
    }
  ],
  "pagination": { /* ... */ }
}
```

#### GET /api/v1/sboms/{sbom_id}/risk-score
**Description**: Get aggregate risk score for SBOM
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "sbom_id": "sbom_uuid",
    "overall_score": 52.3,
    "critical_count": 0,
    "high_count": 3,
    "medium_count": 8,
    "low_count": 15,
    "threat_count": 2,
    "remediable_count": 5,
    "calculated_at": "2026-07-08T10:00:00Z",
    "trend": "increasing"
  }
}
```

#### GET /api/v1/components/{component_id}/recommendations
**Description**: Get remediation recommendations
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "rec_uuid",
      "component_id": "component_uuid",
      "recommendation_type": "update_available",
      "target_version": "4.18.3",
      "estimated_effort": "low",
      "risk_reduction_percent": 45,
      "reason": "Patch available for 2 vulnerabilities",
      "created_at": "2026-07-08T10:00:00Z"
    }
  ]
}
```

---

## 8. Compliance Service APIs

### 8.1 Policy Endpoints

#### GET /api/v1/compliance/policies
**Description**: List compliance policies
**Authentication**: Bearer token (Compliance role+)
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "policy_uuid",
      "name": "NIST Cybersecurity Framework",
      "policy_type": "nist",
      "description": "Policy for NIST compliance",
      "is_active": true,
      "created_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

#### POST /api/v1/compliance/reports
**Description**: Generate compliance report
**Authentication**: Bearer token (Security role+)
**Request**:
```json
{
  "report_type": "nist",
  "sbom_id": "sbom_uuid",
  "include_remediation": true
}
```
**Response (202 Accepted)**:
```json
{
  "success": true,
  "data": {
    "report_id": "report_uuid",
    "status": "generating",
    "estimated_completion": "2026-07-08T10:35:00Z"
  }
}
```

#### GET /api/v1/compliance/reports/{report_id}
**Description**: Get compliance report
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "report_uuid",
    "report_type": "nist",
    "sbom_id": "sbom_uuid",
    "status": "completed",
    "compliance_score": 78.5,
    "findings": [
      {
        "finding_id": "finding_uuid",
        "severity": "high",
        "description": "Finding description",
        "remediation": "Remediation steps"
      }
    ],
    "generated_at": "2026-07-08T10:33:00Z"
  }
}
```

#### GET /api/v1/audit-logs
**Description**: Get audit logs
**Authentication**: Bearer token (Compliance role+)
**Query Parameters**:
- `user_id` (optional)
- `action_type` (optional): created, updated, deleted, exported
- `resource_type` (optional)
- `limit`, `offset`, `sort`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "log_uuid",
      "user_id": "user_uuid",
      "action_type": "created",
      "resource_type": "sbom",
      "resource_id": "sbom_uuid",
      "changes": {
        "format": "cyclonedx-json",
        "component_count": 145
      },
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2026-07-08T10:00:00Z"
    }
  ],
  "pagination": { /* ... */ }
}
```

---

## 9. Project Management APIs

### 9.1 Project Endpoints

#### POST /api/v1/projects
**Description**: Create new project
**Authentication**: Bearer token
**Request**:
```json
{
  "name": "My Project",
  "description": "Project description",
  "repository_url": "https://github.com/owner/repo",
  "repository_type": "github"
}
```
**Response (201)**:
```json
{
  "success": true,
  "data": {
    "id": "project_uuid",
    "name": "My Project",
    "slug": "my-project",
    "organization_id": "org_uuid",
    "created_at": "2026-07-08T10:00:00Z"
  }
}
```

#### GET /api/v1/projects
**Description**: List projects
**Authentication**: Bearer token
**Query Parameters**: `limit`, `offset`, `sort`
**Response (200)**:
```json
{
  "success": true,
  "data": [
    {
      "id": "project_uuid",
      "name": "My Project",
      "slug": "my-project",
      "sbom_count": 5,
      "last_scan": "2026-07-08T10:00:00Z",
      "risk_score": 45.2,
      "created_at": "2026-07-08T10:00:00Z"
    }
  ],
  "pagination": { /* ... */ }
}
```

#### GET /api/v1/projects/{project_id}
**Description**: Get project details
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "id": "project_uuid",
    "name": "My Project",
    "slug": "my-project",
    "description": "Project description",
    "repository_url": "https://github.com/owner/repo",
    "sbom_count": 5,
    "vulnerability_count": 3,
    "risk_score": 45.2,
    "last_scan": "2026-07-08T10:00:00Z",
    "created_at": "2026-07-08T10:00:00Z"
  }
}
```

#### PUT /api/v1/projects/{project_id}
**Description**: Update project
**Authentication**: Bearer token (Admin role+)
**Request**:
```json
{
  "name": "Updated Project Name",
  "description": "Updated description"
}
```
**Response (200)**: Updated project object

#### DELETE /api/v1/projects/{project_id}
**Description**: Delete project
**Authentication**: Bearer token (Admin role+)
**Response (204)**: No content

---

## 10. Container Service APIs

### 10.1 Container Endpoints

#### POST /api/v1/containers/scan
**Description**: Scan container image
**Authentication**: Bearer token
**Request**:
```json
{
  "registry": "docker.io",
  "image_name": "myapp",
  "image_tag": "latest",
  "deep_scan": true
}
```
**Response (202 Accepted)**:
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_uuid",
    "status": "processing"
  }
}
```

#### GET /api/v1/containers/{scan_id}
**Description**: Get container scan results
**Authentication**: Bearer token
**Response (200)**:
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_uuid",
    "registry": "docker.io",
    "image_name": "myapp",
    "image_tag": "latest",
    "digest": "sha256:abc123...",
    "status": "completed",
    "vulnerability_count": 5,
    "critical_count": 0,
    "high_count": 2,
    "sbom": { /* Embedded SBOM */ },
    "completed_at": "2026-07-08T10:33:00Z"
  }
}
```

---

## 11. API Error Codes

| Code | Meaning | Example |
|---|---|---|
| `VALIDATION_ERROR` | Request validation failed | Invalid email format |
| `AUTHENTICATION_REQUIRED` | Missing authentication | No Bearer token provided |
| `UNAUTHORIZED` | Insufficient permissions | User not in admin role |
| `NOT_FOUND` | Resource not found | SBOM not found |
| `CONFLICT` | Resource conflict | Email already registered |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit | 1000 requests/minute exceeded |
| `INTERNAL_ERROR` | Server error | Unexpected error |
| `SERVICE_UNAVAILABLE` | Service down | Database connection failed |
| `ASYNC_PROCESSING` | Still processing | Check back later with job_id |

---

## 12. OpenAPI/Swagger Specification

**File**: openapi.yaml (will be auto-generated)

**Example Partial Spec**:
```yaml
openapi: 3.0.0
info:
  title: AI Supply Chain Security Platform
  version: 1.0.0
  description: SBOM generation, vulnerability scanning, threat detection

servers:
  - url: https://api.sbom.io/api/v1
    description: Production

paths:
  /sboms:
    get:
      summary: List SBOMs
      operationId: listSboms
      tags:
        - SBOMs
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            default: 20
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SbomListResponse'
    post:
      summary: Create SBOM
      operationId: createSbom
      tags:
        - SBOMs
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateSbomRequest'
      responses:
        '201':
          description: Created

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    Sbom:
      type: object
      properties:
        id:
          type: string
          format: uuid
        project_id:
          type: string
          format: uuid
        format:
          type: string
          enum: [cyclonedx-json, spdx-json]
        component_count:
          type: integer
        vulnerability_count:
          type: integer
        created_at:
          type: string
          format: date-time
```

---

## 13. Rate Limiting Examples

**Scenario 1: User at 90% of limit**
```
GET /api/v1/sboms HTTP/1.1
Authorization: Bearer token_here

HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 100
X-RateLimit-Reset: 1657264200
```

**Scenario 2: User exceeds limit**
```
GET /api/v1/sboms HTTP/1.1
Authorization: Bearer token_here

HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1657264200

{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again after 60 seconds."
  }
}
```

---

## 14. API Versioning Strategy

### 14.1 Version Management

**Current Version**: v1 (all endpoints under /api/v1)

**Future Versions**: v2, v3, etc. maintained in parallel for 6+ months

**Breaking Changes**:
- Require major version bump
- Old versions deprecated with 6-month notice
- Clients must migrate to new version

**Non-Breaking Changes**:
- New optional fields (backward compatible)
- New endpoints (no version bump)
- Deprecated fields (with notice)

---

## 15. Webhook API

### 15.1 Webhook Events

**Supported Events**:
- `sbom.generated`
- `sbom.scan_complete`
- `vulnerability.detected`
- `threat.detected`
- `risk_score.updated`
- `compliance.report_ready`

**Webhook Format**:
```json
{
  "event": "sbom.generated",
  "timestamp": "2026-07-08T10:30:00Z",
  "data": {
    "sbom_id": "sbom_uuid",
    "project_id": "project_uuid",
    "component_count": 145
  },
  "delivery_id": "delivery_uuid"
}
```

### 15.2 Webhook Subscription

#### POST /api/v1/webhooks
**Request**:
```json
{
  "url": "https://your-app.com/webhooks/sbom",
  "events": ["sbom.generated", "sbom.scan_complete"],
  "active": true
}
```
**Response (201)**:
```json
{
  "success": true,
  "data": {
    "id": "webhook_uuid",
    "url": "https://your-app.com/webhooks/sbom",
    "events": ["sbom.generated", "sbom.scan_complete"],
    "active": true,
    "secret": "webhook_secret_here",
    "created_at": "2026-07-08T10:00:00Z"
  }
}
```

---

## 16. API Endpoint Summary

**Total Endpoints**: 60+

| Service | Endpoints | Status |
|---|---|---|
| Authentication | 8 | ✅ Defined |
| SBOM | 12 | ✅ Defined |
| Vulnerabilities | 8 | ✅ Defined |
| Threats | 6 | ✅ Defined |
| Risk Scoring | 6 | ✅ Defined |
| Compliance | 6 | ✅ Defined |
| Projects | 5 | ✅ Defined |
| Containers | 4 | ✅ Defined |
| Webhooks | 4 | ✅ Defined |
| **TOTAL** | **59** | **✅ Complete** |

---

## 17. Performance Targets

| Metric | Target | Mechanism |
|---|---|---|
| Auth response | <50ms | Token validation cache |
| SBOM list | <100ms | Database indices |
| Component lookup | <20ms | Primary key index |
| Threat detection | <500ms (async) | Background workers |
| Report generation | <5 seconds (async) | Background workers |
| API p95 latency | <500ms | Caching, indexing |
| API p99 latency | <1000ms | Acceptable |

---

## 18. Security Standards in APIs

- ✅ **JWT Authentication**: Secure token-based auth
- ✅ **HTTPS Only**: TLS 1.3 enforcement
- ✅ **Input Validation**: All requests validated
- ✅ **Output Encoding**: All responses safe
- ✅ **Rate Limiting**: DDoS protection
- ✅ **CORS**: Strict origin whitelist
- ✅ **CSRF Protection**: SameSite cookies
- ✅ **Audit Logging**: All actions logged

---

## 19. Phase 4 Deliverables

- [x] API design principles documented
- [x] Global API standards defined
- [x] 60+ endpoints specified
- [x] Request/response schemas
- [x] Error handling standards
- [x] Rate limiting policies
- [x] Webhook API designed
- [x] OpenAPI specification framework
- [x] Performance targets
- [x] Security standards

---

## 20. Next Steps

### Phase 5: Implementation (Kickoff)

**Ready for**:
1. Backend API development (FastAPI)
2. Frontend integration
3. Database layer development
4. Test suite creation
5. Docker containerization
6. Kubernetes deployment

**Timeline**: 8-12 weeks for MVP

---

**Document Control**
- Version: 1.0
- Status: COMPLETE
- Last Updated: 2026-07-08
- Next Phase: Phase 5 (Implementation)
- Expected Implementation Start: 2026-07-15
