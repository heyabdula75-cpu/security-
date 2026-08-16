# ============================================================================
# Quick Setup - SQLite Version (No PostgreSQL Required)
# ============================================================================
# Use this to get started immediately. Upgrade to PostgreSQL later.
# ============================================================================

param(
    [switch]$UseSQLite
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Color output helpers
function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $colors = @{
        "SUCCESS" = "Green"
        "ERROR"   = "Red"
        "WARNING" = "Yellow"
        "INFO"    = "Cyan"
    }
    if ($null -eq $colors[$Type]) {
        $color = "White"
    } else {
        $color = $colors[$Type]
    }
    
    $symbol = ""
    switch ($Type) {
        "SUCCESS" { $symbol = "[OK]" }
        "ERROR"   { $symbol = "[ERROR]" }
        "WARNING" { $symbol = "[WARN]" }
        "INFO"    { $symbol = "[>>]" }
    }
    Write-Host "$symbol $Message" -ForegroundColor $color
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SecureChain Platform - Quick Setup (SQLite)                  ║" -ForegroundColor Cyan
Write-Host "║  Ready to use in 5 minutes. PostgreSQL optional.              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Check Python
Write-Status "Checking Python..." "INFO"
try {
    $pythonVersion = & python --version 2>&1
    Write-Status "Python: $pythonVersion" "SUCCESS"
} catch {
    Write-Status "Python not found. Install Python 3.11+ from https://www.python.org/downloads/" "ERROR"
    exit 1
}

# Create venv
Write-Host ""
Write-Status "Creating Python virtual environment..." "INFO"
if (-not (Test-Path ".venv")) {
    & python -m venv .venv
    Write-Status "Virtual environment created" "SUCCESS"
} else {
    Write-Status "Virtual environment already exists" "WARNING"
}

# Activate venv
Write-Status "Activating virtual environment..." "INFO"
& ".\.venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host ""
Write-Status "Installing Python dependencies..." "INFO"
$backendDir = Join-Path $scriptRoot "src\backend"
& pip install -q -r (Join-Path $backendDir "requirements.txt")
Write-Status "Dependencies installed" "SUCCESS"

# Create .env for SQLite
Write-Host ""
Write-Status "Creating .env configuration (SQLite)..." "INFO"
$envContent = @"
# SQLite Configuration (Development)
DATABASE_URL=sqlite+aiosqlite:///./sbom_platform.db
DATABASE_ECHO=False

# Application Settings
APP_NAME=SBOM Platform
APP_VERSION=1.0.0
DEBUG=True
SECRET_KEY=dev-secret-key-$(Get-Random -Maximum 10000)
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis (Optional)
REDIS_URL=redis://localhost:6379/0

# CORS
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000","http://127.0.0.1:5173","http://127.0.0.1:3000"]

# Features
ENABLE_MFA=False
ENABLE_WEBHOOKS=True
ENABLE_ASYNC_PROCESSING=True
"@

Set-Content -Path ".\.env" -Value $envContent -Encoding UTF8
Write-Status ".env file created" "SUCCESS"

# Initialize database
Write-Host ""
Write-Status "Initializing database schema..." "INFO"
$pythonCode = @"
import asyncio, sys
sys.path.insert(0, 'src/backend')
from app.db_init import initialize_database_from_settings

async def init():
    try:
        engine = await initialize_database_from_settings(echo=False)
        print("Database initialized successfully")
        await engine.dispose()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

asyncio.run(init())
"@

& python -c $pythonCode
if ($LASTEXITCODE -ne 0) {
    Write-Status "Database initialization failed - continuing anyway" "WARNING"
} else {
    Write-Status "Database schema initialized" "SUCCESS"
}

# Launch backend
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✓ Setup Complete! Starting Backend Server...                ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Access points:" -ForegroundColor Cyan
Write-Host "  • API Docs: http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "  • ReDoc: http://127.0.0.1:8000/redoc" -ForegroundColor White
Write-Host ""

# Start browser
Write-Status "Opening API documentation..." "INFO"
Start-Process "http://127.0.0.1:8000/docs"
Start-Sleep -Milliseconds 500

# Start server
Write-Status "Starting Uvicorn (Press Ctrl+C to stop)..." "INFO"
Write-Host ""
Push-Location (Join-Path $scriptRoot "src\backend")
& python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
