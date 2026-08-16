@echo off
REM ═══════════════════════════════════════════════════════════
REM SecureChain — Docker Development Deployment
REM ═══════════════════════════════════════════════════════════

setlocal enabledelayedexpansion

echo.
echo 🐳 SecureChain Docker Development Setup
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
echo 🔨 Building Docker images...
echo ─────────────────────────────────────────
%COMPOSE_CMD% -f docker-compose.dev.yml build

if errorlevel 1 (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo ✅ Build complete

echo.
echo 🚀 Starting development services...
echo ─────────────────────────────────────────
%COMPOSE_CMD% -f docker-compose.dev.yml up

REM Note: This will keep running, Ctrl+C to stop
