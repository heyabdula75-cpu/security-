@echo off
REM ═══════════════════════════════════════════════════════════
REM SecureChain — Quick Development Setup
REM ═══════════════════════════════════════════════════════════

echo.
echo 🚀 SecureChain Development Setup
echo ═══════════════════════════════════════════════════════════
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo 📦 Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created
)

REM Activate virtual environment
echo.
echo 🔌 Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install dependencies
echo.
echo 📥 Installing Python dependencies...
pip install -q -r src/backend/requirements.txt
if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)
echo ✅ Dependencies installed

REM Create .env if not exists
if not exist "src\backend\.env" (
    echo.
    echo 🔧 Creating development .env file...
    (
        echo # Development Environment Configuration
        echo DATABASE_URL=sqlite+aiosqlite:///./sbom_platform.db
        echo DEBUG=True
        echo SECRET_KEY=dev-secret-key-change-in-production
        echo CORS_ORIGINS=["http://localhost:5173","http://localhost:3000","http://127.0.0.1:5173"]
        echo ENABLE_MFA=False
        echo ENABLE_WEBHOOKS=True
        echo ENABLE_ASYNC_PROCESSING=True
    ) > src\backend\.env
    echo ✅ Created .env
)

echo.
echo 🎯 Setup complete! Ready to start development...
echo ═══════════════════════════════════════════════════════════
echo.
echo 📝 Next Steps (run in 2 separate terminals):
echo.
echo Terminal 1 - Backend Server:
echo   cd src\backend
echo   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
echo.
echo Terminal 2 - Frontend Server:
echo   cd frontend
echo   python -m http.server 5173
echo.
echo 🌐 Open in browser: http://127.0.0.1:5173
echo 📖 API Docs: http://127.0.0.1:8000/docs
echo.
echo ═══════════════════════════════════════════════════════════

pause
