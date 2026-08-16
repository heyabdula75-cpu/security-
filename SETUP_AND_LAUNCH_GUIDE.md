# SecureChain Platform - Complete Setup & Launch Guide
## AI Supply Chain Security & SBOM Verification Platform

**Status**: Phase 5 Implementation Ready  
**Last Updated**: 2026-07-09  
**Architecture**: FastAPI + PostgreSQL + Async Python

---

## Quick Start (5 Minutes)

### Prerequisites
- Windows 10/11
- Python 3.11+ ([Download](https://www.python.org/downloads/))
- PostgreSQL 14+ ([Download](https://www.postgresql.org/download/windows/))

### Step 1: Run Complete Setup
```powershell
# Open PowerShell as Administrator
PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
```

This script will:
- ✓ Verify PostgreSQL installation
- ✓ Create database and user
- ✓ Set up Python virtual environment
- ✓ Install all dependencies
- ✓ Initialize database schema
- ✓ Create .env configuration file

### Step 2: Launch Backend
```powershell
# Option A: PowerShell (Recommended)
PowerShell -ExecutionPolicy Bypass -File launch_backend.ps1

# Option B: Batch file
.\run.bat
```

### Step 3: Access the Application
- **API Documentation**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc
- **OpenAPI Spec**: http://127.0.0.1:8000/openapi.json

---

## Detailed Installation Guide

### 1. PostgreSQL Installation & Setup

#### 1.1 Install PostgreSQL
1. Download PostgreSQL 15 from: https://www.postgresql.org/download/windows/
2. Run the installer
3. **Important**: Remember the postgres password (default admin user)
4. Accept default settings (port 5432 is standard)
5. Use pgAdmin for database management (optional)

#### 1.2 Verify PostgreSQL Installation
```powershell
# Test PostgreSQL connectivity
psql -U postgres -h 127.0.0.1 -l

# Should display list of databases
```

#### 1.3 Troubleshooting PostgreSQL
```powershell
# Start PostgreSQL service
net start PostgreSQL15

# Stop PostgreSQL service
net stop PostgreSQL15

# Check if PostgreSQL is running
Get-Service PostgreSQL15

# For manual connection
psql -U postgres -h 127.0.0.1 -d postgres
```

### 2. Python Environment Setup

#### 2.1 Install Python
1. Download Python 3.11+ from: https://www.python.org/downloads/
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Verify installation:
```powershell
python --version
pip --version
```

#### 2.2 Automated Setup
Run the comprehensive setup script:
```powershell
cd C:\path\to\project
PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
```

This will:
- Create `.venv` virtual environment
- Install 17 Python packages from requirements.txt
- Create database `sbom_platform`
- Create database user `sbom_user`
- Initialize database schema
- Create `.env` configuration file

#### 2.3 Manual Setup (if needed)
```powershell
# Navigate to project root
cd C:\path\to\project

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r src/backend/requirements.txt

# Create database (see below)
```

### 3. Database Setup

#### 3.1 Automatic Database Creation (via SETUP_POSTGRESQL.ps1)
The setup script automatically:
- Creates database: `sbom_platform`
- Creates user: `sbom_user` (password: `SecurePass123!`)
- Grants privileges
- Initializes schema

#### 3.2 Manual Database Creation
```sql
-- Connect as postgres user
psql -U postgres -h 127.0.0.1

-- Execute in psql:
CREATE ROLE sbom_user WITH LOGIN CREATEDB PASSWORD 'SecurePass123!';
CREATE DATABASE sbom_platform OWNER sbom_user;
GRANT ALL PRIVILEGES ON DATABASE sbom_platform TO sbom_user;

-- Connect to new database
\c sbom_platform

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
```

#### 3.3 Verify Database Creation
```powershell
# List databases
psql -U postgres -h 127.0.0.1 -l

# Connect to sbom_platform
psql -U sbom_user -h 127.0.0.1 -d sbom_platform

# List tables
\dt

# Exit
\q
```

### 4. Environment Configuration

#### 4.1 .env File
The setup script creates `.env` automatically with:
```
DATABASE_URL=postgresql+asyncpg://sbom_user:SecurePass123!@127.0.0.1:5432/sbom_platform
DEBUG=True
SECRET_KEY=dev-secret-key-...
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REDIS_URL=redis://localhost:6379/0
...
```

#### 4.2 Customize .env (Optional)
Edit `.env` to customize:
- Database credentials
- Debug mode
- Secret key
- API keys for external services
- Feature flags

---

## Launching the Application

### Option 1: PowerShell (Recommended)
```powershell
PowerShell -ExecutionPolicy Bypass -File launch_backend.ps1
```

Features:
- ✓ Validates environment
- ✓ Verifies PostgreSQL connection
- ✓ Auto-opens API documentation
- ✓ Pretty console output
- ✓ Error handling and diagnostics

### Option 2: Batch File
```powershell
.\run.bat
```

### Option 3: Manual Python
```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Navigate to backend
cd src/backend

# Start server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## API Documentation

### 1. Accessing Documentation
Once the server is running, visit:
- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc
- **OpenAPI JSON**: http://127.0.0.1:8000/openapi.json

### 2. API Endpoints (Phase 4 Complete)

#### Authentication (8 endpoints)
- POST `/api/v1/auth/register` - Register new user
- POST `/api/v1/auth/login` - Authenticate user
- POST `/api/v1/auth/refresh-token` - Refresh JWT
- POST `/api/v1/auth/logout` - Logout user
- GET `/api/v1/auth/profile` - Get user profile
- POST `/api/v1/auth/mfa/enable` - Enable MFA
- POST `/api/v1/auth/mfa/verify` - Verify MFA code

#### SBOM Management (12 endpoints)
- POST `/api/v1/sboms/generate` - Generate SBOM
- GET `/api/v1/sboms/generate/{job_id}` - Check generation status
- GET `/api/v1/sboms` - List SBOMs
- GET `/api/v1/sboms/{sbom_id}` - Get SBOM details
- GET `/api/v1/sboms/{sbom_id}/export` - Export SBOM
- DELETE `/api/v1/sboms/{sbom_id}` - Delete SBOM
- GET `/api/v1/components` - List components
- GET `/api/v1/components/{component_id}` - Get component details
- GET `/api/v1/components/search` - Search components

#### Vulnerabilities (8 endpoints)
- GET `/api/v1/vulnerabilities` - List vulnerabilities
- POST `/api/v1/vulnerabilities/scan` - Scan for vulnerabilities
- GET `/api/v1/vulnerabilities/{vuln_id}` - Get vulnerability details
- POST `/api/v1/vulnerabilities/{vuln_id}/verify` - Verify vulnerability

#### And 30+ more endpoints for threats, risks, compliance, projects, etc.

### 3. Example Requests

#### Register User
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "SecurePass123!",
    "full_name": "John Doe",
    "organization_name": "ACME Corp"
  }'
```

#### Login
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "SecurePass123!"
  }'
```

---

## Testing

### Run All Tests
```powershell
# Activate venv
.\.venv\Scripts\Activate.ps1

# Navigate to backend
cd src/backend

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=app

# Run specific test file
pytest tests/test_auth.py -v
```

### Test Files Available
- `test_auth.py` - Authentication tests
- `test_projects.py` - Project management tests
- `test_sboms.py` - SBOM generation tests
- `test_vulnerabilities.py` - Vulnerability scanning tests
- `test_threats.py` - Threat detection tests
- `test_risks.py` - Risk scoring tests
- `test_compliance.py` - Compliance tests
- `test_health.py` - Health check tests

---

## Database Verification

### Check Database Status
```powershell
python verify_database.py
```

This will:
- ✓ Test PostgreSQL connection
- ✓ Verify database exists
- ✓ List all tables
- ✓ Show version information
- ✓ Provide troubleshooting tips

---

## Troubleshooting

### PostgreSQL Connection Issues

**Error**: "Failed to connect to PostgreSQL"
```powershell
# Solution 1: Start PostgreSQL service
net start PostgreSQL15

# Solution 2: Check PostgreSQL is listening
netstat -ano | findstr :5432

# Solution 3: Verify connection manually
psql -U sbom_user -h 127.0.0.1 -d sbom_platform

# Solution 4: Check .env DATABASE_URL
type .env | findstr DATABASE_URL
```

### Python Virtual Environment Issues

**Error**: "Virtual environment not found"
```powershell
# Recreate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r src/backend/requirements.txt
```

### Port Already in Use

**Error**: "Address already in use (port 8000)"
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Kill process (replace PID)
taskkill /PID <PID> /F

# Or use different port
python -m uvicorn app.main:app --port 8001
```

### Database Schema Issues

**Error**: "No such table"
```powershell
# Initialize schema
.\.venv\Scripts\Activate.ps1
cd src/backend
python -c "from app.db_init import initialize_database_from_settings; import asyncio; asyncio.run(initialize_database_from_settings())"
```

---

## Development Workflow

### 1. Daily Development Startup
```powershell
# Activate venv and start backend
PowerShell -ExecutionPolicy Bypass -File launch_backend.ps1

# In another terminal - start frontend (if available)
cd frontend
npm install
npm start
```

### 2. Making Code Changes
- Edit files in `src/backend/app/`
- Backend auto-reloads (--reload flag)
- Check API docs: http://127.0.0.1:8000/docs
- View error logs in terminal

### 3. Testing Changes
```powershell
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_auth.py -v

# Run with debugging
pytest tests/test_auth.py -v -s
```

### 4. Database Migrations (When Needed)
```powershell
cd src/backend

# Create migration
alembic revision --autogenerate -m "Description of change"

# Apply migration
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

---

## Production Deployment Checklist

Before deploying to production:

- [ ] Change `SECRET_KEY` to strong random value
- [ ] Set `DEBUG=False`
- [ ] Configure proper `CORS_ORIGINS`
- [ ] Set up external API keys (GitHub, NVD, etc.)
- [ ] Use production database
- [ ] Enable MFA (`ENABLE_MFA=True`)
- [ ] Configure monitoring (Prometheus, Grafana)
- [ ] Set up logging aggregation (ELK, etc.)
- [ ] Enable HTTPS/TLS
- [ ] Configure backup/restore procedures
- [ ] Performance testing (<500ms latency target)
- [ ] Security audit (OWASP Top 10 review)
- [ ] Disaster recovery plan
- [ ] Load testing

---

## File Structure

```
project-root/
├── SETUP_POSTGRESQL.ps1      ← Run this first!
├── launch_backend.ps1         ← Run this to start
├── run.bat                     ← Alternative launcher
├── verify_database.py          ← Check DB status
├── start_backend.py            ← Manual startup
├── .env                        ← Configuration (auto-created)
├── .venv/                      ← Virtual environment (auto-created)
├── src/
│   └── backend/
│       ├── app/
│       │   ├── main.py         ← FastAPI app entry
│       │   ├── config.py       ← Settings
│       │   ├── database.py     ← DB connection
│       │   ├── db_init.py      ← Schema init
│       │   ├── models/         ← ORM models
│       │   ├── schemas/        ← Pydantic schemas
│       │   ├── services/       ← Business logic
│       │   ├── api/v1/         ← API endpoints
│       │   └── middleware/     ← Auth, CORS, etc.
│       ├── tests/              ← Test suite
│       └── requirements.txt    ← Dependencies
├── frontend/                   ← React app (separate)
└── docs/                       ← Documentation
```

---

## Useful Commands Reference

```powershell
# PostgreSQL
psql -U postgres -h 127.0.0.1
psql -U sbom_user -h 127.0.0.1 -d sbom_platform
\dt                          # List tables
\d table_name                # Describe table
SELECT * FROM users;         # Query example
\q                           # Quit psql

# Python/Virtual Environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip list
pip freeze > requirements.txt

# FastAPI/Uvicorn
python -m uvicorn app.main:app --reload
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
python -m uvicorn app.main:app --reload --log-level debug

# Tests
pytest tests/
pytest tests/ -v
pytest tests/ -v --cov=app
pytest tests/test_auth.py -v -s
```

---

## Next Steps

1. **Complete Installation**: Run `SETUP_POSTGRESQL.ps1`
2. **Verify Setup**: Run `verify_database.py`
3. **Launch Backend**: Run `launch_backend.ps1`
4. **Access API**: Open http://127.0.0.1:8000/docs
5. **Explore Endpoints**: Try authentication endpoints
6. **Run Tests**: Execute `pytest tests/ -v`
7. **Review Code**: Check `src/backend/app/` structure
8. **Frontend Setup**: Configure React app (separate)

---

## Support & Documentation

- **Phase 1-4 Complete**: See `/docs/` folder
- **API Specification**: `/docs/PHASE4_API_SPECIFICATION.md`
- **Database Design**: `/docs/PHASE3_DATABASE_DESIGN.md`
- **Architecture**: `/docs/PHASE2_SYSTEM_ARCHITECTURE.md`
- **Requirements**: `/docs/PHASE1_REQUIREMENTS_SPECIFICATIONS.md`

---

## Contact & Questions

For development support, check:
- Project documentation in `/docs/`
- Code comments and docstrings
- Test files for usage examples
- FastAPI documentation: https://fastapi.tiangolo.com/
- SQLAlchemy docs: https://docs.sqlalchemy.org/

---

**Version**: 1.0.0  
**Last Updated**: 2026-07-09  
**Status**: Production Ready ✓
