@echo off
title SecureChain — Install Dependencies
color 0B

echo.
echo  ===================================================
echo    SecureChain AI Supply Chain Security Platform
echo    Dependency Installer
echo  ===================================================
echo.

:: Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Please install Python 3.11+ and add it to PATH.
    echo  Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  [OK] Python detected:
python --version

echo.
echo  [INFO] Checking virtual environment...

:: Create venv if it doesn't exist
if not exist ".venv\Scripts\activate.bat" (
    echo  [INFO] Creating virtual environment (.venv)...
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
) else (
    echo  [OK] Virtual environment already exists.
)

echo.
echo  [INFO] Installing backend dependencies...
echo.

.venv\Scripts\python -m pip install --upgrade pip --quiet
.venv\Scripts\python -m pip install -r src\backend\requirements.txt

if errorlevel 1 (
    echo.
    echo  [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo  ===================================================
echo   [SUCCESS] Installation complete!
echo  ===================================================
echo.
echo   Run the platform with:   run.bat
echo   API Documentation at:    http://localhost:8000/docs
echo   Web Dashboard at:        http://localhost:8000
echo.
pause
