@echo off
REM ============================================================================
REM Python Installation & Setup Fix
REM This script will help you get Python 3.11+ installed properly
REM ============================================================================

title Python Setup Fix - SecureChain Platform

echo.
echo  ====================================================================
echo    Python Installation Helper
echo    Fixing Windows Python Configuration
echo  ====================================================================
echo.

echo  [INFO] Current Python Status:
echo.
where.exe python 2>nul
if errorlevel 1 (
    echo  Python not found in PATH
) else (
    echo  Python alias found in: %ERRORLEVEL%
)

echo.
echo  [INFO] Python Locations to Check:
echo  - C:\Program Files\Python311
echo  - C:\Program Files\Python312
echo  - C:\Program Files (x86)\Python311
echo  - C:\Users\%USERNAME%\AppData\Local\Programs\Python

echo.
echo  [SOLUTION] You have two options:
echo.
echo  OPTION 1: Remove Microsoft Store Python Alias (Quick Fix)
echo  ──────────────────────────────────────────────────────────
echo  1. Press Win+I to open Settings
echo  2. Go to: Apps ^> Apps & Features ^> App Execution Aliases
echo  3. Find "python.exe" and "python3.exe"
echo  4. Toggle them OFF
echo  5. Close Settings and try again
echo.
echo  OPTION 2: Install Python 3.11+ from python.org (Recommended)
echo  ────────────────────────────────────────────────────────────
echo  1. Go to: https://www.python.org/downloads/
echo  2. Download Python 3.11 or 3.12 (Windows 64-bit)
echo  3. Run the installer
echo  4. CHECK: "Add Python to PATH" ✓
echo  5. Click "Install Now"
echo  6. After installation, close and reopen this terminal
echo.
echo  OPTION 3: Use Python from Microsoft Store (If Installed)
echo  ──────────────────────────────────────────────────────────
echo  The Microsoft Store Python app is installed but disabled by alias.
echo  Fix via Option 1 above to enable it.
echo.

echo  ====================================================================
echo    After fixing, run: .\QUICK_START.bat
echo  ====================================================================
echo.

pause
