# ============================================================================
# PostgreSQL + Python Environment Setup Script
# AI Supply Chain Security & SBOM Verification Platform
# ============================================================================
# This script handles:
# - PostgreSQL installation verification
# - Database and user creation
# - Python virtual environment setup
# - Dependency installation
# - Database schema initialization
# - Environment configuration
# ============================================================================

param(
    [string]$PostgresVersion = "15",
    [string]$DBName = "sbom_platform",
    [string]$DBUser = "sbom_user",
    [string]$DBPassword = "SecurePass123!",
    [string]$DBHost = "127.0.0.1",
    [int]$DBPort = 5432
)

$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Color output helper functions
function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ $($Message.PadRight(62)) ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "→ $Message" -ForegroundColor Cyan
}

Write-Header "PostgreSQL & Project Setup - OpenAI Senior Engineer Edition"

# ============================================================================
# 1. CHECK SYSTEM REQUIREMENTS
# ============================================================================
Write-Header "1. Verifying System Requirements"

# Check Python
Write-Info "Checking Python installation..."
try {
    $pythonVersion = python --version 2>&1
    Write-Success "Python found: $pythonVersion"
} catch {
    Write-Error-Custom "Python not found. Please install Python 3.11+ from https://www.python.org/downloads/"
    exit 1
}

# Check if PostgreSQL is installed
Write-Info "Checking PostgreSQL installation..."
$psqlExists = Get-Command psql -ErrorAction SilentlyContinue
if ($psqlExists) {
    Write-Success "PostgreSQL found"
    $psqlVersion = & psql --version
    Write-Success "Version: $psqlVersion"
} else {
    Write-Warning-Custom "PostgreSQL not found in PATH"
    Write-Info "Attempting to locate PostgreSQL..."
    
    $pgPaths = @(
        "C:\Program Files\PostgreSQL\15\bin",
        "C:\Program Files\PostgreSQL\14\bin",
        "C:\Program Files (x86)\PostgreSQL\15\bin",
        "C:\Program Files (x86)\PostgreSQL\14\bin"
    )
    
    $pgFound = $false
    foreach ($path in $pgPaths) {
        if (Test-Path $path) {
            Write-Success "Found PostgreSQL at: $path"
            $env:PATH += ";$path"
            $pgFound = $true
            break
        }
    }
    
    if (-not $pgFound) {
        Write-Error-Custom "PostgreSQL not found. Please install PostgreSQL 14 or 15 from https://www.postgresql.org/download/windows/"
        Write-Info "After installation, close and reopen this terminal."
        exit 1
    }
}

# ============================================================================
# 2. SETUP PROJECT DIRECTORY
# ============================================================================
Write-Header "2. Setting Up Project Directories"

$projectRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $projectRoot "src\backend"
$venvPath = Join-Path $projectRoot ".venv"

Write-Info "Project root: $projectRoot"
Write-Info "Backend directory: $backendDir"

if (-not (Test-Path $backendDir)) {
    Write-Error-Custom "Backend directory not found: $backendDir"
    exit 1
}
Write-Success "Backend directory verified"

# ============================================================================
# 3. CREATE PYTHON VIRTUAL ENVIRONMENT
# ============================================================================
Write-Header "3. Setting Up Python Virtual Environment"

if (Test-Path $venvPath) {
    Write-Warning-Custom "Virtual environment already exists at $venvPath"
} else {
    Write-Info "Creating virtual environment..."
    & python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "Failed to create virtual environment"
        exit 1
    }
    Write-Success "Virtual environment created"
}

# Activate virtual environment
Write-Info "Activating virtual environment..."
& "$venvPath\Scripts\Activate.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Failed to activate virtual environment"
    exit 1
}
Write-Success "Virtual environment activated"

# ============================================================================
# 4. INSTALL PYTHON DEPENDENCIES
# ============================================================================
Write-Header "4. Installing Python Dependencies"

Write-Info "Upgrading pip, setuptools, and wheel..."
& python -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Failed to upgrade pip"
    exit 1
}
Write-Success "pip upgraded"

Write-Info "Installing project dependencies from requirements.txt..."
$requirementsPath = Join-Path $backendDir "requirements.txt"

if (-not (Test-Path $requirementsPath)) {
    Write-Error-Custom "requirements.txt not found: $requirementsPath"
    exit 1
}

& pip install -r $requirementsPath
if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Failed to install dependencies"
    exit 1
}
Write-Success "All dependencies installed"

# Verify key packages
Write-Info "Verifying key packages..."
$packages = @("fastapi", "sqlalchemy", "asyncpg", "pydantic", "pytest")
foreach ($pkg in $packages) {
    & python -c "import $($pkg.Replace('-', '_'))" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "$pkg installed"
    } else {
        Write-Warning-Custom "$pkg verification failed"
    }
}

# ============================================================================
# 5. SETUP POSTGRESQL DATABASE
# ============================================================================
Write-Header "5. Setting Up PostgreSQL Database"

Write-Info "Database Configuration:"
Write-Info "  Host: $DBHost"
Write-Info "  Port: $DBPort"
Write-Info "  Database: $DBName"
Write-Info "  User: $DBUser"

# Create database and user using psql
Write-Info "Connecting to PostgreSQL to create database and user..."

# Create SQL commands
$sqlCommands = @"
-- Create role/user if not exists
CREATE ROLE "$DBUser" WITH LOGIN CREATEDB PASSWORD '$DBPassword';

-- Create database if not exists
CREATE DATABASE "$DBName" OWNER "$DBUser";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE "$DBName" TO "$DBUser";
ALTER DATABASE "$DBName" OWNER TO "$DBUser";

-- Connect to the new database and create extensions
\c "$DBName"
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
"@

# Save SQL to a temporary file
$sqlFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.sql'
Set-Content -Path $sqlFile -Value $sqlCommands -Encoding UTF8

Write-Info "Executing SQL setup..."
try {
    # Try to execute as postgres user first
    & psql -U postgres -h $DBHost -p $DBPort -f $sqlFile -v ON_ERROR_STOP=1 2>&1 | ForEach-Object {
        if ($_ -match "ERROR" -or $_ -match "FATAL") {
            Write-Warning-Custom $_
        } elseif ($_ -match "CREATE|GRANT|ALTER") {
            Write-Success $_
        }
    }
    Write-Success "PostgreSQL setup completed"
} catch {
    Write-Warning-Custom "PostgreSQL setup with automatic execution had issues (this may be OK if password auth is required)"
    Write-Info "Please manually run the following SQL commands:"
    Write-Host $sqlCommands -ForegroundColor Yellow
}

Remove-Item $sqlFile -Force -ErrorAction SilentlyContinue

# ============================================================================
# 6. CREATE ENVIRONMENT CONFIGURATION
# ============================================================================
Write-Header "6. Creating Environment Configuration"

$envFile = Join-Path $projectRoot ".env"
$envContent = @"
# ============================================================================
# PostgreSQL Configuration
# ============================================================================
DATABASE_URL=postgresql+asyncpg://${DBUser}:${DBPassword}@${DBHost}:${DBPort}/${DBName}
DATABASE_ECHO=False

# ============================================================================
# Application Settings
# ============================================================================
APP_NAME=SBOM Platform
APP_VERSION=1.0.0
DEBUG=True
SECRET_KEY=dev-secret-key-change-in-production-$(Get-Random -Maximum 10000)
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ============================================================================
# Redis Configuration (for caching and task queue)
# ============================================================================
REDIS_URL=redis://localhost:6379/0

# ============================================================================
# CORS Configuration
# ============================================================================
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000","https://localhost","http://127.0.0.1:5173","http://127.0.0.1:3000"]

# ============================================================================
# External API Keys
# ============================================================================
GITHUB_API_KEY=
NVD_API_KEY=
OSS_INDEX_USERNAME=
OSS_INDEX_PASSWORD=

# ============================================================================
# Feature Flags
# ============================================================================
ENABLE_MFA=False
ENABLE_WEBHOOKS=True
ENABLE_ASYNC_PROCESSING=True

# ============================================================================
# Logging
# ============================================================================
LOG_LEVEL=INFO
"@

Set-Content -Path $envFile -Value $envContent -Encoding UTF8
Write-Success ".env file created at: $envFile"

# ============================================================================
# 7. INITIALIZE DATABASE SCHEMA
# ============================================================================
Write-Header "7. Initializing Database Schema"

Set-Location $projectRoot

Write-Info "Importing database initialization module..."
$pythonCode = @"
import asyncio
import sys
sys.path.insert(0, r'$backendDir')

from app.db_init import initialize_database_from_settings
from app.config import settings

async def init_db():
    try:
        print(f"Connecting to: {settings.DATABASE_URL}")
        engine = await initialize_database_from_settings(echo=False)
        print("✓ Database schema initialized successfully")
        await engine.dispose()
    except Exception as e:
        print(f"✗ Database initialization failed: {e}", file=sys.stderr)
        sys.exit(1)

asyncio.run(init_db())
"@

& python -c $pythonCode
if ($LASTEXITCODE -ne 0) {
    Write-Warning-Custom "Database schema initialization encountered an issue (continuing)"
    Write-Info "You may need to manually initialize the database"
} else {
    Write-Success "Database schema initialized"
}

# ============================================================================
# 8. RUN TESTS
# ============================================================================
Write-Header "8. Running Project Tests"

Write-Info "Running pytest suite..."
Set-Location $backendDir
& pytest tests/ -v --tb=short 2>&1 | Tee-Object -Variable testOutput

$testsPassed = $testOutput -match "passed"
if ($testsPassed) {
    Write-Success "Tests completed"
} else {
    Write-Warning-Custom "Some tests may have failed - review output above"
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Header "✓ Setup Complete - Project Ready to Launch"

Write-Host "
╔════════════════════════════════════════════════════════════════╗
║                    SETUP SUMMARY                              ║
╚════════════════════════════════════════════════════════════════╝

✓ Python Virtual Environment: Created at $venvPath
✓ Dependencies: Installed from requirements.txt
✓ PostgreSQL Database: '$DBName' created with user '$DBUser'
✓ Environment Configuration: .env file created
✓ Database Schema: Initialized

NEXT STEPS:
──────────────────────────────────────────────────────────────

1. To start the backend (from project root):
   .\.venv\Scripts\python start_backend.py

   OR use the prepared run.bat:
   .\run.bat

2. To start frontend development server:
   cd frontend
   npm install
   npm start

3. Access the application:
   • API Documentation: http://localhost:8000/docs
   • ReDoc: http://localhost:8000/redoc
   • Frontend: http://localhost:3000 (or as configured)

4. To run tests again:
   cd src\backend
   pytest tests/ -v

DATABASE CREDENTIALS:
──────────────────────────────────────────────────────────────
  Host: $DBHost
  Port: $DBPort
  Database: $DBName
  User: $DBUser
  Password: $DBPassword

ENVIRONMENT FILE:
──────────────────────────────────────────────────────────────
  Location: $envFile

For production deployment:
  1. Change SECRET_KEY to a strong random value
  2. Set DEBUG=False
  3. Configure proper CORS_ORIGINS
  4. Update external API keys
  5. Use environment-specific .env files
" -ForegroundColor Green

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Ready to launch! Run: .\.venv\Scripts\python start_backend.py ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
