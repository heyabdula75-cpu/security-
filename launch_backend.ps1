# ============================================================================
# Master Launch Script - SecureChain Platform
# AI Supply Chain Security & SBOM Verification Platform
# ============================================================================
# This script handles complete startup sequence:
# - Validates environment
# - Starts backend API server
# - Opens documentation in browser
# - Provides helpful debugging information
# ============================================================================

param(
    [switch]$SkipBrowser,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot

# Color output helpers
function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $colors = @{
        "SUCCESS" = "Green"
        "ERROR"   = "Red"
        "WARNING" = "Yellow"
        "INFO"    = "Cyan"
    }
    $color = $colors[$Type] ?? "White"
    $symbol = switch ($Type) {
        "SUCCESS" { "✓" }
        "ERROR"   { "✗" }
        "WARNING" { "⚠" }
        "INFO"    { "→" }
        default   { " " }
    }
    Write-Host "$symbol $Message" -ForegroundColor $color
}

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ $($Message.PadRight(62)) ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "■ $Message" -ForegroundColor Yellow
    Write-Host ("-" * 66) -ForegroundColor DarkGray
}

# ============================================================================
# STARTUP SEQUENCE
# ============================================================================

Write-Header "SecureChain Platform - Backend Launch"

# 1. VERIFY ENVIRONMENT
Write-Section "1. Verifying Environment"

# Check Python
Write-Status "Checking Python..." "INFO"
try {
    $pythonVersion = & python --version 2>&1
    Write-Status "Python: $pythonVersion" "SUCCESS"
} catch {
    Write-Status "Python not found" "ERROR"
    exit 1
}

# Check venv
if (-not (Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Status "Virtual environment not found" "ERROR"
    Write-Status "Run: PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1" "INFO"
    exit 1
}
Write-Status "Virtual environment found" "SUCCESS"

# Check .env
if (-not (Test-Path ".\.env")) {
    Write-Status ".env file not found" "ERROR"
    Write-Status "Run: PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1" "INFO"
    exit 1
}
Write-Status ".env file found" "SUCCESS"

# 2. ACTIVATE ENVIRONMENT
Write-Section "2. Activating Virtual Environment"

Write-Status "Activating venv..." "INFO"
& ".\.venv\Scripts\Activate.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Status "Failed to activate virtual environment" "ERROR"
    exit 1
}
Write-Status "Virtual environment activated" "SUCCESS"

# 3. VERIFY DATABASE
Write-Section "3. Verifying Database Connection"

Write-Status "Testing PostgreSQL connection..." "INFO"
$dbVerifyCode = @"
import asyncio, sys
sys.path.insert(0, 'src/backend')
from app.config import settings
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def test():
    try:
        engine = create_async_engine(settings.DATABASE_URL, echo=False)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}")

asyncio.run(test())
"@

$dbTest = & python -c $dbVerifyCode 2>&1
if ($dbTest -eq "OK") {
    Write-Status "PostgreSQL connection verified" "SUCCESS"
} else {
    Write-Status "PostgreSQL connection failed: $dbTest" "WARNING"
    Write-Status "Database may need initialization. Run: python verify_database.py" "INFO"
}

# 4. START BACKEND SERVER
Write-Section "4. Starting Backend API Server"

$backendDir = Join-Path $scriptRoot "src\backend"

Write-Host ""
Write-Status "Backend Configuration:" "INFO"
Write-Host "  • Host: 127.0.0.1" -ForegroundColor Gray
Write-Host "  • Port: 8000" -ForegroundColor Gray
Write-Host "  • API Docs: http://127.0.0.1:8000/docs" -ForegroundColor Gray
Write-Host "  • ReDoc: http://127.0.0.1:8000/redoc" -ForegroundColor Gray
Write-Host "  • OpenAPI JSON: http://127.0.0.1:8000/openapi.json" -ForegroundColor Gray

if (-not $SkipBrowser) {
    Write-Host ""
    Write-Status "Opening API documentation..." "INFO"
    Start-Process "http://127.0.0.1:8000/docs"
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Status "Starting Uvicorn server (Press Ctrl+C to stop)..." "INFO"
Write-Host ("-" * 66) -ForegroundColor DarkGray
Write-Host ""

Push-Location $backendDir
try {
    $env:PYTHONUNBUFFERED = 1
    & python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
} finally {
    Pop-Location
}

Write-Host ""
Write-Host ("-" * 66) -ForegroundColor DarkGray
Write-Status "Backend server stopped" "INFO"

# Cleanup on exit
Write-Host ""
Write-Status "Deactivating virtual environment..." "INFO"
