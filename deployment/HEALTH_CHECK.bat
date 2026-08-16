@echo off
REM ═══════════════════════════════════════════════════════════
REM SecureChain — Health Check & Monitoring
REM ═══════════════════════════════════════════════════════════

setlocal enabledelayedexpansion

echo.
echo 🏥 SecureChain System Health Check
echo ═══════════════════════════════════════════
echo.

REM Check Backend
echo 📊 Checking Backend...
timeout /t 1 /nobreak > nul
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Backend running at http://127.0.0.1:8000
) else (
    echo ❌ Backend not responding at http://127.0.0.1:8000
)

REM Check Frontend
echo.
echo 📊 Checking Frontend...
timeout /t 1 /nobreak > nul
curl -s http://127.0.0.1:5173 >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Frontend running at http://127.0.0.1:5173
) else (
    echo ❌ Frontend not responding at http://127.0.0.1:5173
)

REM Check API Documentation
echo.
echo 📊 Checking API Docs...
timeout /t 1 /nobreak > nul
curl -s http://127.0.0.1:8000/docs >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ API Swagger UI available at http://127.0.0.1:8000/docs
) else (
    echo ❌ API Docs not responding
)

REM Check Database (if running locally)
echo.
echo 📊 Checking Database...
if exist "src\backend\sbom_platform.db" (
    for /f "tokens=*" %%A in ('powershell -Command "(Get-Item 'src\backend\sbom_platform.db').Length / 1MB"') do set SIZE=%%A
    echo ✅ SQLite database found (approx !SIZE!MB)
) else (
    echo ⚠️  SQLite database not found - will be created on first run
)

REM Port availability
echo.
echo 📊 Checking Ports...
for %%P in (8000 5173 6379 5432) do (
    netstat -ano 2>nul | find ":%%P" >nul
    if !errorlevel! equ 0 (
        echo ✅ Port %%P is in use
    ) else (
        echo ⚠️  Port %%P is available
    )
)

REM Summary
echo.
echo ═══════════════════════════════════════════
echo 📋 System Status Summary
echo ═══════════════════════════════════════════
echo.
echo 🌐 Frontend:  http://127.0.0.1:5173
echo 🔌 Backend:   http://127.0.0.1:8000
echo 📖 API Docs:  http://127.0.0.1:8000/docs
echo 🗄️  Database:  SQLite (src/backend/sbom_platform.db)
echo.
echo ═══════════════════════════════════════════
echo.

pause
