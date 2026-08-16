@echo off
REM ═══════════════════════════════════════════════════════════
REM SecureChain — Production Deployment Setup
REM ═══════════════════════════════════════════════════════════

setlocal enabledelayedexpansion

echo.
echo 🚀 SecureChain Production Deployment Setup
echo ═══════════════════════════════════════════
echo.

REM Check Docker is installed
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Docker not found! Please install Docker Desktop.
    pause
    exit /b 1
)

echo ✅ Docker found

REM Check Docker Compose
where docker-compose >nul 2>nul
if %errorlevel% neq 0 (
    echo ⚠️  Using 'docker compose' (V2)...
    set COMPOSE_CMD=docker compose
) else (
    set COMPOSE_CMD=docker-compose
)

echo.
echo 📋 Production Environment Configuration
echo ─────────────────────────────────────────

REM Prompt for configuration
set /p POSTGRES_PASSWORD="Enter PostgreSQL password (min 16 chars): "
if "%POSTGRES_PASSWORD%"=="" (
    echo ❌ Password cannot be empty!
    pause
    exit /b 1
)

REM Generate SECRET_KEY
for /f "tokens=*" %%A in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET_KEY=%%A

set /p DOMAIN="Enter domain name (e.g., yourdomain.com): "
if "%DOMAIN%"=="" set DOMAIN=localhost

echo.
echo 🔧 Configuring services...
echo ─────────────────────────────────────────

REM Create .env file
(
    echo # Production Environment Configuration
    echo # Generated on %date% %time%
    echo.
    echo POSTGRES_USER=sbom_admin
    echo POSTGRES_PASSWORD=%POSTGRES_PASSWORD%
    echo SECRET_KEY=%SECRET_KEY%
    echo DOMAIN=%DOMAIN%
) > .env.prod

echo ✅ Created .env.prod

REM Pull latest images
echo.
echo 📥 Pulling Docker images...
%COMPOSE_CMD% -f docker-compose.prod.yml pull

REM Build images
echo.
echo 🔨 Building Docker images...
%COMPOSE_CMD% -f docker-compose.prod.yml build --no-cache

REM Start services
echo.
echo 🚀 Starting production services...
%COMPOSE_CMD% -f docker-compose.prod.yml up -d

REM Wait for services to start
timeout /t 10 /nobreak

REM Check health
echo.
echo 🏥 Checking service health...
echo ─────────────────────────────────────────

%COMPOSE_CMD% -f docker-compose.prod.yml ps

echo.
echo ✅ Production deployment complete!
echo.
echo 📊 Access Points:
echo ─────────────────────────────────────────
echo Frontend:    http://%DOMAIN%
echo API Docs:    http://%DOMAIN%/docs
echo ReDoc:       http://%DOMAIN%/redoc
echo Backend:     http://%DOMAIN%/api/v1
echo.
echo 📝 Useful Commands:
echo ─────────────────────────────────────────
echo View logs:        %COMPOSE_CMD% -f docker-compose.prod.yml logs -f
echo Stop services:    %COMPOSE_CMD% -f docker-compose.prod.yml down
echo Restart service:  %COMPOSE_CMD% -f docker-compose.prod.yml restart backend
echo.

pause
