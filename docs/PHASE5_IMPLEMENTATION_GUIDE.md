# Phase 5: Core Module Implementation
## MVP Development Guide

**Status**: IN PROGRESS 🚀
**Date**: 2026-07-08
**Duration**: 8-12 weeks
**Target Completion**: September 2026

---

## 1. Phase 5 Overview

### 1.1 Objectives

Build a **production-ready MVP** of the AI Supply Chain Security & SBOM Verification Platform with:
- ✅ Core SBOM generation and management
- ✅ Vulnerability scanning and reporting
- ✅ Basic threat detection
- ✅ Risk scoring system
- ✅ Web dashboard UI
- ✅ REST APIs (all 60+ endpoints)
- ✅ Authentication & RBAC
- ✅ Database with TimescaleDB
- ✅ Docker containerization
- ✅ Kubernetes deployment
- ✅ CI/CD pipeline

### 1.2 Success Criteria

| Criterion | Target | Status |
|---|---|---|
| All 60+ APIs functional | 100% | ⏳ In progress |
| SBOM analysis latency | <100ms p95 | ⏳ To measure |
| Vulnerability scan latency | <500ms | ⏳ To measure |
| Dashboard responsiveness | <200ms | ⏳ To measure |
| API uptime (7 days) | 99.5%+ | ⏳ To measure |
| Test coverage | >80% | ⏳ In progress |
| Security scan results | PASS | ⏳ Pending |
| Performance benchmarks | PASS | ⏳ In progress |

### 1.3 MVP Scope (39 Must-Have Features)

**Authentication & Users** (3 features):
- User registration & login
- JWT token management
- User profiles

**Project Management** (4 features):
- Create/manage projects
- Link to repositories
- Project dashboards
- Project settings

**SBOM Generation** (5 features):
- Generate SBOM from GitHub repo
- Support multiple SBOM formats
- Store SBOM versions
- Export SBOM
- View SBOM contents

**Vulnerability Scanning** (6 features):
- Scan for vulnerabilities
- Display vulnerability results
- Filter/sort vulnerabilities
- Vulnerability severity levels
- Affected components list
- Remediation recommendations

**Risk Scoring** (4 features):
- Calculate component risk scores
- Aggregate SBOM risk scores
- Risk trending
- Risk recommendations

**Dashboard & Reporting** (5 features):
- Project dashboard
- Vulnerability summary
- Risk overview
- Audit logs
- Basic reporting

**Threat Detection** (3 features):
- Typosquatting detection
- Package integrity checks
- Basic malware detection

**Admin & Settings** (4 features):
- User management
- Organization settings
- API key management
- Audit logs

---

## 2. Sprint Breakdown (12-Week Timeline)

### Sprint 1-2: Foundation & Core Backend (Weeks 1-2)
**Focus**: Project setup, database, auth

- [ ] Set up development environment
- [ ] Configure PostgreSQL + TimescaleDB
- [ ] Create FastAPI project structure
- [ ] Implement user authentication (JWT)
- [ ] Create database models (SQLAlchemy)
- [ ] Set up database migrations
- [ ] Implement user management endpoints
- [ ] Unit tests for auth module
- **Deliverable**: Authentication system + database schema running

### Sprint 3-4: API Development - Part 1 (Weeks 3-4)
**Focus**: SBOM & Project APIs

- [ ] Implement SBOM endpoints (POST, GET, list)
- [ ] Implement project management endpoints
- [ ] Create SBOM generation service
- [ ] Integrate with GitHub API
- [ ] Implement SBOM storage
- [ ] Create component endpoints
- [ ] Unit & integration tests
- **Deliverable**: Full SBOM generation pipeline working

### Sprint 5-6: API Development - Part 2 (Weeks 5-6)
**Focus**: Vulnerability & Risk APIs

- [ ] Implement vulnerability endpoints
- [ ] Integrate vulnerability data sources (NVD, OSS Index)
- [ ] Implement vulnerability scanning service
- [ ] Implement risk scoring algorithms
- [ ] Create risk score endpoints
- [ ] Add recommendation engine
- [ ] Unit & integration tests
- **Deliverable**: Vulnerability scanning working end-to-end

### Sprint 7-8: Frontend - Part 1 (Weeks 7-8)
**Focus**: UI scaffolding & dashboards

- [ ] Set up React project (Vite)
- [ ] Create layout & navigation
- [ ] Build authentication UI
- [ ] Implement user login/registration
- [ ] Create project management UI
- [ ] Build project dashboard
- [ ] Responsive design
- [ ] Unit tests
- **Deliverable**: Dashboard UI functional

### Sprint 9-10: Frontend - Part 2 (Weeks 9-10)
**Focus**: Feature UIs & integration

- [ ] Build SBOM viewer UI
- [ ] Create vulnerability report UI
- [ ] Build risk scoring UI
- [ ] Create audit logs UI
- [ ] API integration (all endpoints)
- [ ] Error handling & validation
- [ ] UX polish
- [ ] Unit & E2E tests
- **Deliverable**: Full UI functional with backend

### Sprint 11-12: DevOps, Testing & Optimization (Weeks 11-12)
**Focus**: Containerization, deployment, performance

- [ ] Docker containerization (backend, frontend, DB)
- [ ] Kubernetes manifests
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Load testing
- [ ] Security testing
- [ ] Documentation
- [ ] Bug fixes & polish
- **Deliverable**: MVP ready for deployment

---

## 3. Technology Stack Confirmation

### 3.1 Backend Stack

**Framework**: FastAPI 0.104+
- Async-first, performant
- Automatic OpenAPI docs
- Built-in validation (Pydantic)

**Database**:
- PostgreSQL 15+ (primary data store)
- TimescaleDB 2.10+ (time-series metrics)
- Redis 7.0+ (caching, sessions)
- Elasticsearch 8.0+ (audit logs)

**ORMs & Libraries**:
- SQLAlchemy 2.0+ (ORM)
- Alembic (database migrations)
- Pydantic (validation)
- PyJWT (authentication)
- httpx (HTTP client)
- pytest (testing)

**External Services**:
- GitHub API (repository access)
- NVD API (vulnerability data)
- OSS Index API (open source vulnerabilities)
- Syft/Grype (SBOM generation)

### 3.2 Frontend Stack

**Framework**: React 18.2+
- Component-based UI
- Fast refresh development
- Large ecosystem

**Build Tool**: Vite 5.0+
- Fast development server
- Lightning-fast builds
- Native ES modules

**Libraries**:
- TypeScript (type safety)
- Tailwind CSS (styling)
- React Query (data fetching)
- Zustand (state management)
- React Router (routing)
- Axios (HTTP client)
- Vitest (unit testing)
- Playwright (E2E testing)

### 3.3 DevOps Stack

**Containerization**: Docker
- Multi-stage builds
- Optimized images

**Orchestration**: Kubernetes
- Pod scaling
- Service mesh (optional)
- ConfigMaps/Secrets

**CI/CD**: GitHub Actions
- Automated tests
- Build & push Docker images
- Deploy to staging/prod

**Infrastructure-as-Code**: Terraform
- Infrastructure provisioning
- Reproducible deployments

---

## 4. Project Structure

### 4.1 Directory Layout

```
sbom-platform/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI app entry
│   │   ├── config.py               # Configuration
│   │   ├── database.py             # Database setup
│   │   │
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth.py         # Auth endpoints
│   │   │   │   ├── sboms.py        # SBOM endpoints
│   │   │   │   ├── projects.py     # Project endpoints
│   │   │   │   ├── vulnerabilities.py
│   │   │   │   ├── risks.py        # Risk endpoints
│   │   │   │   ├── threats.py      # Threat endpoints
│   │   │   │   ├── compliance.py   # Compliance endpoints
│   │   │   │   └── containers.py   # Container endpoints
│   │   │   └── v2/                 # Future versions
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py             # User model
│   │   │   ├── project.py          # Project model
│   │   │   ├── sbom.py             # SBOM model
│   │   │   ├── vulnerability.py    # Vulnerability model
│   │   │   ├── risk.py             # Risk model
│   │   │   └── audit_log.py        # Audit log model
│   │   │
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py             # Auth request/response schemas
│   │   │   ├── user.py
│   │   │   ├── sbom.py
│   │   │   ├── vulnerability.py
│   │   │   └── risk.py
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── auth_service.py     # Auth business logic
│   │   │   ├── sbom_service.py     # SBOM generation/management
│   │   │   ├── vulnerability_service.py
│   │   │   ├── risk_service.py     # Risk calculation
│   │   │   ├── threat_service.py   # Threat detection
│   │   │   └── compliance_service.py
│   │   │
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py             # Auth middleware
│   │   │   ├── logging.py          # Request logging
│   │   │   └── error_handling.py   # Error handling
│   │   │
│   │   ├── utils/
│   │   │   ├── __init__.py
│   │   │   ├── jwt_utils.py        # JWT utilities
│   │   │   ├── password_utils.py   # Password hashing
│   │   │   ├── validators.py       # Custom validators
│   │   │   └── helpers.py          # Helper functions
│   │   │
│   │   └── integrations/
│   │       ├── __init__.py
│   │       ├── github.py           # GitHub API integration
│   │       ├── nvd.py              # NVD API integration
│   │       ├── oss_index.py        # OSS Index integration
│   │       └── syft.py             # Syft SBOM generation
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py             # Pytest configuration
│   │   ├── test_auth.py            # Auth tests
│   │   ├── test_sbom.py            # SBOM tests
│   │   ├── test_vulnerability.py   # Vulnerability tests
│   │   ├── test_risk.py            # Risk tests
│   │   ├── integration/
│   │   │   ├── test_auth_flow.py
│   │   │   ├── test_sbom_flow.py
│   │   │   └── test_scan_flow.py
│   │   └── e2e/
│   │       └── test_end_to_end.py
│   │
│   ├── alembic/
│   │   ├── versions/               # Migration files
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── alembic.ini
│   │
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile
│   ├── .env.example
│   └── README.md
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout/
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── Layout.tsx
│   │   │   ├── Auth/
│   │   │   │   ├── LoginForm.tsx
│   │   │   │   ├── RegisterForm.tsx
│   │   │   │   └── ProtectedRoute.tsx
│   │   │   ├── Dashboard/
│   │   │   │   ├── ProjectDashboard.tsx
│   │   │   │   ├── RiskOverview.tsx
│   │   │   │   └── VulnerabilityWidget.tsx
│   │   │   ├── Projects/
│   │   │   │   ├── ProjectList.tsx
│   │   │   │   ├── ProjectDetail.tsx
│   │   │   │   └── ProjectForm.tsx
│   │   │   ├── SBOM/
│   │   │   │   ├── SBOMList.tsx
│   │   │   │   ├── SBOMViewer.tsx
│   │   │   │   └── ComponentTree.tsx
│   │   │   ├── Vulnerabilities/
│   │   │   │   ├── VulnerabilityList.tsx
│   │   │   │   ├── VulnerabilityDetail.tsx
│   │   │   │   └── VulnerabilityFilter.tsx
│   │   │   └── Common/
│   │   │       ├── Button.tsx
│   │   │       ├── Modal.tsx
│   │   │       ├── Table.tsx
│   │   │       └── Loading.tsx
│   │   │
│   │   ├── pages/
│   │   │   ├── Home.tsx
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Projects.tsx
│   │   │   ├── SBOM.tsx
│   │   │   ├── Vulnerabilities.tsx
│   │   │   ├── Risks.tsx
│   │   │   └── NotFound.tsx
│   │   │
│   │   ├── services/
│   │   │   ├── api.ts              # API client setup
│   │   │   ├── auth.ts             # Auth service
│   │   │   ├── sbom.ts             # SBOM API calls
│   │   │   ├── vulnerabilities.ts  # Vulnerability API calls
│   │   │   ├── risks.ts            # Risk API calls
│   │   │   └── projects.ts         # Project API calls
│   │   │
│   │   ├── store/
│   │   │   ├── auth.store.ts       # Auth state (Zustand)
│   │   │   ├── ui.store.ts         # UI state
│   │   │   └── data.store.ts       # Data state
│   │   │
│   │   ├── hooks/
│   │   │   ├── useAuth.ts
│   │   │   ├── useProject.ts
│   │   │   ├── useSBOM.ts
│   │   │   ├── useVulnerabilities.ts
│   │   │   └── useRisks.ts
│   │   │
│   │   ├── types/
│   │   │   ├── api.ts              # API type definitions
│   │   │   ├── models.ts           # Data models
│   │   │   └── auth.ts             # Auth types
│   │   │
│   │   ├── styles/
│   │   │   ├── globals.css
│   │   │   ├── variables.css
│   │   │   └── components.css
│   │   │
│   │   ├── utils/
│   │   │   ├── format.ts           # Formatting utilities
│   │   │   ├── validation.ts       # Validation utilities
│   │   │   └── constants.ts        # Constants
│   │   │
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   │
│   ├── tests/
│   │   ├── unit/
│   │   │   └── components.test.tsx
│   │   ├── integration/
│   │   │   └── auth.test.tsx
│   │   └── e2e/
│   │       └── login.spec.ts
│   │
│   ├── public/
│   │   └── favicon.ico
│   │
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── .env.example
│   ├── Dockerfile
│   └── README.md
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
│
├── kubernetes/
│   ├── backend-deployment.yaml
│   ├── backend-service.yaml
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   ├── postgres-deployment.yaml
│   ├── postgres-service.yaml
│   ├── redis-deployment.yaml
│   ├── redis-service.yaml
│   ├── config-map.yaml
│   └── ingress.yaml
│
├── ci-cd/
│   ├── .github/
│   │   └── workflows/
│   │       ├── test.yaml           # Run tests on PR
│   │       ├── build.yaml          # Build Docker images
│   │       ├── deploy-staging.yaml # Deploy to staging
│   │       └── deploy-prod.yaml    # Deploy to production
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SETUP.md
│   ├── API.md
│   ├── DATABASE.md
│   └── DEPLOYMENT.md
│
├── .gitignore
├── .env.example
├── docker-compose.yml              # Local development
├── README.md
└── CONTRIBUTING.md
```

---

## 5. Development Environment Setup

### 5.1 Prerequisites

**Required Tools**:
- Git (for version control)
- Docker & Docker Compose (for local DB)
- Node.js 18+ (for frontend)
- Python 3.11+ (for backend)
- PostgreSQL 15+ (for data)
- Redis 7.0+ (for cache)
- Kubernetes (k3s or Docker Desktop)

### 5.2 Local Development Setup

**Step 1: Clone repository**
```bash
git clone https://github.com/your-org/sbom-platform.git
cd sbom-platform
```

**Step 2: Set up environment variables**
```bash
# Backend
cp backend/.env.example backend/.env
# Edit backend/.env with database credentials

# Frontend
cp frontend/.env.example frontend/.env
# Edit frontend/.env with API endpoint
```

**Step 3: Start PostgreSQL + Redis (Docker)**
```bash
docker-compose up -d postgres redis
# Wait for containers to be ready
sleep 10
```

**Step 4: Backend setup**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# API available at http://localhost:8000/docs
```

**Step 5: Frontend setup**
```bash
cd frontend
npm install
npm run dev
# Frontend available at http://localhost:5173
```

### 5.3 Development Workflow

**Daily Development**:
```bash
# Terminal 1: Backend
cd backend && source venv/bin/activate && uvicorn app.main:app --reload

# Terminal 2: Frontend
cd frontend && npm run dev

# Terminal 3: Database (if not using docker-compose)
docker-compose up postgres redis

# Visit http://localhost:5173 in browser
```

---

## 6. Core Modules Implementation

### 6.1 Authentication Module

**Components**:
- User registration endpoint
- Login endpoint with JWT issuance
- Token refresh endpoint
- User profile endpoint
- MFA (future)

**Database Model**:
```python
# models/user.py
class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID, primary_key=True, default=uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String)
    organization_id = Column(UUID, ForeignKey("organizations.id"))
    roles = relationship("Role", secondary="user_roles")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)
```

**API Endpoints**:
- `POST /api/v1/auth/register` - Create account
- `POST /api/v1/auth/login` - Get JWT token
- `POST /api/v1/auth/refresh-token` - Refresh token
- `GET /api/v1/auth/profile` - Get user profile
- `POST /api/v1/auth/logout` - Invalidate token

### 6.2 SBOM Service Module

**Components**:
- SBOM generation (from GitHub)
- SBOM storage
- SBOM export (multiple formats)
- Component analysis

**Key Features**:
- Integrate with Syft for SBOM generation
- Support CycloneDX and SPDX formats
- Version tracking
- Component relationship mapping

**API Endpoints**:
- `POST /api/v1/sboms/generate` - Start generation (async)
- `GET /api/v1/sboms/{sbom_id}` - Get SBOM details
- `GET /api/v1/sboms` - List SBOMs
- `GET /api/v1/components` - List components
- `GET /api/v1/components/{component_id}` - Component details

### 6.3 Vulnerability Scanning Module

**Components**:
- Vulnerability data ingestion
- Component scanning
- Result aggregation
- Severity calculation

**Data Sources**:
- National Vulnerability Database (NVD)
- OSS Index
- GitHub Security Advisories

**API Endpoints**:
- `POST /api/v1/vulnerabilities/scan` - Start scan (async)
- `GET /api/v1/vulnerabilities` - List vulnerabilities
- `GET /api/v1/vulnerabilities/{vulnerability_id}` - Details

### 6.4 Risk Scoring Module

**Components**:
- Component risk calculation
- SBOM risk aggregation
- Risk trending
- Recommendation engine

**Risk Factors**:
- Vulnerability count and severity
- Component age and maintenance status
- Transitive dependencies
- Known exploits

**API Endpoints**:
- `GET /api/v1/sboms/{sbom_id}/risk-score` - SBOM risk
- `GET /api/v1/components/{component_id}/recommendations` - Recommendations

### 6.5 Threat Detection Module

**Components**:
- Typosquatting detection
- Malware scanning
- Dependency confusion detection

**API Endpoints**:
- `POST /api/v1/threats/detect` - Start detection (async)
- `GET /api/v1/threats` - List detected threats

---

## 7. API Implementation Priority

### Phase 5A: Critical APIs (Weeks 1-4)

**Priority 1** (Weeks 1-2):
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/profile`
- `POST /api/v1/projects`
- `GET /api/v1/projects`

**Priority 2** (Weeks 3-4):
- `POST /api/v1/sboms/generate`
- `GET /api/v1/sboms/{sbom_id}`
- `GET /api/v1/components`
- `POST /api/v1/vulnerabilities/scan`
- `GET /api/v1/vulnerabilities`

### Phase 5B: Secondary APIs (Weeks 5-8)

**Priority 3** (Weeks 5-6):
- Risk scoring endpoints
- Threat detection endpoints
- Compliance endpoints
- Container scanning endpoints

**Priority 4** (Weeks 7-8):
- Webhook endpoints
- Analytics endpoints
- Admin endpoints

---

## 8. Database Implementation

### 8.1 Migration Strategy

**Using Alembic for database versioning**:

```bash
# Create new migration
alembic revision --autogenerate -m "Add users table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### 8.2 Initial Schema Setup

```python
# Generate from Phase 3 database design
# Create alembic migration with:
# - Users, Roles, Organizations
# - Projects, SBOMs, Components
# - Vulnerabilities, CVEs
# - Risk Scores
# - Audit Logs
# - Threats
```

### 8.3 Seeding Data (Development)

```python
# scripts/seed_db.py
# Create test users, organizations, projects
# Load sample vulnerability data
# Load test SBOMs
```

---

## 9. Testing Strategy

### 9.1 Unit Tests

**Coverage Target**: >80%

**Backend Tests** (pytest):
- Auth module tests
- Service logic tests
- Utility function tests
- Model validation tests

```bash
pytest tests/ -v --cov=app
```

**Frontend Tests** (Vitest):
- Component tests
- Hook tests
- Utility tests

```bash
npm run test
```

### 9.2 Integration Tests

**Database Integration**:
- Test database operations
- Test transactions
- Test migrations

**API Integration**:
- Test endpoint workflows
- Test error handling
- Test rate limiting

### 9.3 End-to-End Tests

**Full User Workflows**:
- User registration → login → create project
- Project → generate SBOM → scan vulnerabilities
- View results → remediate issues

**Tools**: Playwright (frontend), pytest (backend)

---

## 10. Performance Optimization

### 10.1 Backend Optimization

**Database**:
- Add indices for frequently queried columns
- Use connection pooling (pgbouncer)
- Query optimization and explain plans
- Caching layer (Redis)

**API**:
- Response compression (gzip)
- Pagination for large datasets
- Async task processing (Celery)
- Query result caching

### 10.2 Frontend Optimization

**Build**:
- Code splitting by route
- Tree shaking unused code
- Image optimization
- Bundle analysis

**Runtime**:
- Lazy load components
- Memoization of expensive computations
- Virtual scrolling for large lists
- Service workers for offline

### 10.3 Monitoring

**Performance Metrics**:
- API response times (p50, p95, p99)
- Frontend load times
- Database query times
- Cache hit ratios

---

## 11. Security Implementation

### 11.1 Backend Security

- JWT token validation on all endpoints
- RBAC enforcement
- Input validation and sanitization
- SQL injection prevention (SQLAlchemy)
- Password hashing (bcrypt)
- Rate limiting (middleware)
- CORS configuration
- HTTPS/TLS enforcement

### 11.2 Frontend Security

- XSS protection (React escaping)
- CSRF protection (token in headers)
- Secure cookie settings
- Content Security Policy headers
- Dependency scanning (npm audit)

### 11.3 Secrets Management

- Environment variables for sensitive data
- Docker secrets for production
- Kubernetes Secrets for orchestration
- Rotation policies for API keys

---

## 12. Docker & Kubernetes

### 12.1 Docker Images

**Backend Image**:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

**Frontend Image**:
```dockerfile
FROM node:18-alpine as build
WORKDIR /app
COPY package*.json .
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
```

### 12.2 Kubernetes Deployment

**Local Testing** (k3s or Docker Desktop):
```bash
kubectl apply -f kubernetes/
kubectl get pods
kubectl logs -f deployment/backend
```

**Staging/Production**:
- Use managed Kubernetes (EKS, GKE, AKS)
- ConfigMaps for configuration
- Secrets for sensitive data
- StatefulSets for databases
- Persistent volumes for data

---

## 13. CI/CD Pipeline

### 13.1 GitHub Actions Workflow

**Test Pipeline** (on PR):
```yaml
- Run unit tests
- Run integration tests
- Check code coverage
- Lint code
- Security scanning
```

**Build Pipeline** (on merge):
```yaml
- Build Docker images
- Push to container registry
- Run E2E tests on staging
- Generate test reports
```

**Deploy Pipeline** (on tag):
```yaml
- Deploy to production
- Run smoke tests
- Update documentation
```

### 13.2 Deployment Strategy

**Development**: Continuous deployment on merge
**Staging**: Manual approval after tests pass
**Production**: Tagged releases with manual approval

---

## 14. Monitoring & Logging

### 14.1 Application Metrics

**Using Prometheus**:
- HTTP request latency
- Request count by endpoint
- Error rates
- Database query times
- Cache hit ratios

### 14.2 Log Aggregation

**Using ELK Stack / OpenSearch**:
- Application logs
- API request/response logs
- Database logs
- Audit trail logs

### 14.3 Alerting

**Critical Alerts**:
- API error rate > 1%
- Database connection pool exhausted
- High memory/CPU usage
- Deployment failures

---

## 15. Documentation Requirements

### 15.1 API Documentation

- OpenAPI/Swagger spec (auto-generated by FastAPI)
- Endpoint descriptions
- Request/response examples
- Error codes
- Rate limits

**Available at**: `/docs` (Swagger) and `/redoc` (ReDoc)

### 15.2 Code Documentation

- Docstrings for all functions
- Inline comments for complex logic
- Module documentation
- Architecture decisions (ADRs)

### 15.3 User Documentation

- Setup guide
- User manual
- API examples
- Troubleshooting guide

---

## 16. Key Implementation Patterns

### 16.1 Service Layer Pattern

```python
# Separate business logic from API endpoints
# api/v1/sboms.py → calls services/sbom_service.py
# Promotes reusability and testing
```

### 16.2 Repository Pattern

```python
# Abstract database operations
# Makes testing easier with mocks
# Enables easy database swapping
```

### 16.3 Dependency Injection

```python
# FastAPI's Depends() for injecting dependencies
# Makes code more testable
# Reduces coupling
```

### 16.4 Async/Await

```python
# Use async endpoints for non-blocking I/O
# Improves throughput
# Enables processing multiple requests concurrently
```

---

## 17. Common Pitfalls to Avoid

❌ **Don't**:
- Skip error handling
- Ignore performance until end
- Write untestable code
- Mix business logic with API logic
- Hardcode configuration
- Skip database migrations
- Ignore security best practices

✅ **Do**:
- Write tests early
- Use type hints
- Separate concerns
- Document as you go
- Use environment variables
- Implement monitoring early
- Follow security guidelines

---

## 18. Success Checklist

### End of Sprint 2
- [ ] Auth system working
- [ ] Database schema deployed
- [ ] User management endpoints operational
- [ ] 80%+ test coverage

### End of Sprint 4
- [ ] SBOM generation working
- [ ] GitHub integration complete
- [ ] Component storage and retrieval working
- [ ] All SBOM APIs functional

### End of Sprint 6
- [ ] Vulnerability scanning end-to-end
- [ ] Risk scoring algorithms implemented
- [ ] All vulnerability and risk APIs functional

### End of Sprint 8
- [ ] React UI scaffolding complete
- [ ] Dashboard functional
- [ ] Authentication UI complete

### End of Sprint 10
- [ ] All frontend pages complete
- [ ] Full API integration
- [ ] E2E user workflows validated

### End of Sprint 12 (MVP Ready)
- [ ] All 39 must-have features implemented
- [ ] >80% test coverage
- [ ] Security testing passed
- [ ] Performance targets met
- [ ] Documentation complete
- [ ] CI/CD pipeline operational
- [ ] Kubernetes deployment validated
- [ ] Ready for production deployment ✅

---

## 19. Handoff to Production

### 19.1 Pre-Launch Checklist

- [ ] All tests passing
- [ ] Security audit completed
- [ ] Performance benchmarks met
- [ ] Documentation reviewed
- [ ] Team trained
- [ ] Deployment runbook ready
- [ ] Monitoring configured
- [ ] Backup strategy tested
- [ ] Disaster recovery plan ready

### 19.2 Go-Live Process

1. **Preparation** (Day -1)
   - Final code review
   - Database backup
   - Load testing complete
   - Team on-call scheduled

2. **Deployment** (Day 0)
   - Blue-green deployment
   - Smoke tests pass
   - Monitoring active
   - User testing begins

3. **Stabilization** (Day 1-7)
   - Monitor metrics
   - Fix critical issues
   - Gather feedback
   - Document lessons learned

---

## 20. Next Steps (Week of 2026-07-15)

### Immediate Actions

- [ ] Set up GitHub repository
- [ ] Configure development environment
- [ ] Create CI/CD pipelines
- [ ] Set up project management (GitHub Projects)
- [ ] Schedule team kickoff
- [ ] Prepare sprint 1 tasks

### Deliverables for First Sprint

- [ ] Auth system MVP
- [ ] Database deployed
- [ ] Development environment documented
- [ ] User management endpoints
- [ ] Unit tests for auth module

---

**Document Control**
- Version: 1.0
- Status: PHASE 5 START
- Date: 2026-07-08
- Next Review: End of Sprint 2 (2026-07-22)
