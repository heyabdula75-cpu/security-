@echo off
REM ============================================================================
REM Quick Setup - SQLite Version (No PostgreSQL Required)
REM Create Python environment and launch backend in minutes
REM ============================================================================

setlocal enabledelayedexpansion
title SecureChain Quick Start

echo.
echo  ====================================================================
echo    SecureChain Platform - Quick Setup (SQLite)
echo    No PostgreSQL required - Get started in 5 minutes!
echo  ====================================================================
echo.

REM Check Python
echo  [INFO] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found
    echo  Download from: https://www.python.org/downloads/
    echo  Remember to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

python --version
echo  [OK] Python found
echo.

REM Create virtual environment
echo  [INFO] Setting up Python virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo  [OK] Virtual environment created
) else (
    echo  [OK] Virtual environment already exists
)
echo.

REM Activate virtual environment
echo  [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat
echo  [OK] Virtual environment activated
echo.

REM Install dependencies
echo  [INFO] Installing Python dependencies...
echo  This may take 2-3 minutes on first run...
pip install -q -r src\backend\requirements.txt
if errorlevel 1 (
    echo  [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo  [OK] Dependencies installed
echo.

REM Create .env file
echo  [INFO] Creating environment configuration (.env)...
(
    echo # SQLite Configuration - Development
    echo DATABASE_URL=sqlite+aiosqlite:///./sbom_platform.db
    echo DATABASE_ECHO=False
    echo.
    echo # Application Settings
    echo APP_NAME=SBOM Platform
    echo APP_VERSION=1.0.0
    echo DEBUG=True
    echo SECRET_KEY=dev-secret-key-change-later
    echo ALGORITHM=HS256
    echo ACCESS_TOKEN_EXPIRE_MINUTES=30
    echo.
    echo # Redis (Optional
    echo REDIS_URL=redis://localhost:6379/0
    echo.
    echo # CORS
    echo CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]
    echo.
    echo # Features
    echo ENABLE_MFA=False
    echo ENABLE_WEBHOOKS=True
    echo ENABLE_ASYNC_PROCESSING=True
) > .env
echo  [OK] .env configuration created
echo.

REM Initialize database
echo  [INFO] Initializing database schema...
cd src\backend
python -c "import asyncio; import sys; sys.path.insert(0, '.'); from app.db_init import initialize_database_from_settings; asyncio.run(initialize_database_from_settings())" 2>nul
if errorlevel 1 (
    echo  [WARN] Database initialization skipped - will auto-initialize on first run
) else (
    echo  [OK] Database schema initialized
)
cd ..\..
echo.

REM Launch backend
echo.
echo  ====================================================================
echo    SETUP COMPLETE - Starting Backend Server
echo  ====================================================================
echo.
echo  API Documentation: http://127.0.0.1:8000/docs
echo  ReDoc: http://127.0.0.1:8000/redoc
echo.
echo  [INFO] Opening API documentation in browser...
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8000/docs"

echo  [INFO] Starting FastAPI server...
echo  Press Ctrl+C to stop
echo.
echo  ====================================================================
echo.

cd src\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

echo.
echo  [INFO] Server stopped
pause
