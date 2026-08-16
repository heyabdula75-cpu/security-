@echo off
REM ============================================================================
REM SecureChain Platform - Launch Script
REM AI Supply Chain Security & SBOM Verification Platform
REM ============================================================================
REM This script launches the backend API server with PostgreSQL database
REM configuration. It requires setup to have been run first.
REM ============================================================================

title SecureChain — Platform Backend Launch
color 0B

echo.
echo  ===================================================
echo    SecureChain AI Supply Chain Security Platform
echo    Backend Service Launcher
echo  ===================================================
echo.

REM Verify venv exists
if not exist ".venv\Scripts\activate.bat" (
    echo  [ERROR] Virtual environment not found at .\.venv
    echo  Please run the setup first:
    echo.
    echo    PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
    echo.
    pause
    exit /b 1
)

echo  [OK] Virtual environment found.

REM Activate virtual environment
call .\.venv\Scripts\activate.bat

REM Verify .env file exists
if not exist ".env" (
    echo  [ERROR] .env configuration file not found
    echo  Please run the setup first:
    echo.
    echo    PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
    echo.
    pause
    exit /b 1
)

echo  [OK] Environment configuration loaded

REM Set working directory for backend
set BACKEND_DIR=%~dp0src\backend

echo  [INFO] Loading configuration...
echo  [INFO] Configuration Summary:
echo    - Database: PostgreSQL (async driver)
echo    - Backend Directory: %BACKEND_DIR%
echo.

REM Display startup message
echo  [INFO] Starting Uvicorn server...
echo    - Host: 127.0.0.1
echo    - Port: 8000
echo    - Reload: Enabled (development mode)
echo.
echo  ✓ API Documentation: http://127.0.0.1:8000/docs
echo  ✓ ReDoc: http://127.0.0.1:8000/redoc
echo  ✓ OpenAPI JSON: http://127.0.0.1:8000/openapi.json
echo.

REM Open browser automatically
echo  [INFO] Opening API documentation in 2 seconds...
start "" "http://127.0.0.1:8000/docs"
timeout /t 2 /nobreak >nul

echo  [INFO] Press Ctrl+C to stop the server
echo.
cd /d "%BACKEND_DIR%"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Backend startup failed with code %errorlevel%
    echo.
    pause
    exit /b %errorlevel%
)
