# SecureChain Platform - System Requirements & Installation Checklist

## Current Status
❌ Python NOT found in system PATH  
❌ PostgreSQL status unknown  
⏳ Ready to proceed once Python is installed

---

## Step 1: Install Python 3.11+ (REQUIRED - DO THIS FIRST)

### Download Python
1. Open browser and go to: **https://www.python.org/downloads/**
2. Download **Python 3.11** or **3.12** (Windows 64-bit)
   - Click the yellow "Download Python 3.x.x" button
   - Choose 64-bit version (usually recommended)

### Install Python - IMPORTANT STEPS

1. **Run the installer** (`python-3.11.x-amd64.exe` or similar)
2. **CRITICAL**: At the first screen, CHECK the box:
   ```
   ☑ Add Python 3.11 to PATH
   ```
   This is VERY IMPORTANT - many setups fail because this is unchecked!
3. Click "Install Now"
4. Wait for installation to complete (2-3 minutes)
5. Click "Close"

### Verify Python Installation

1. **Close all terminals/PowerShell windows**
2. **Open a NEW PowerShell window** (search "PowerShell" in Start menu)
3. Run this command:
   ```powershell
   python --version
   ```
4. You should see output like:
   ```
   Python 3.11.x
   ```

   ✓ If you see the version, Python is properly installed!
   ✗ If you see "not recognized", Python is not in PATH - see troubleshooting below

---

## Step 2: Install PostgreSQL 15 (OPTIONAL - For Production)

**NOTE**: You can skip this for now and use SQLite instead. PostgreSQL can be installed later.

### If you want PostgreSQL now:
1. Visit: **https://www.postgresql.org/download/windows/**
2. Click "Download the installer"
3. Follow installation (default settings are fine)
4. When prompted for password, remember it!
5. Use port **5432** (default)

### Or use SQLite (Recommended for quick start):
- SQLite is already included with Python
- No additional installation needed
- Perfect for development

---

## Step 3: After Python is Installed - Quick Start

Once Python is installed and verified, run:

```powershell
cd "E:\web peojects\cyber secruty (security+)"
.\QUICK_START.bat
```

This will:
1. ✓ Create Python virtual environment (.venv)
2. ✓ Install 17 Python dependencies
3. ✓ Create SQLite database (sbom_platform.db)
4. ✓ Initialize database schema
5. ✓ Launch FastAPI backend server
6. ✓ Open API documentation in browser

---

## Troubleshooting

### "Python not recognized" after installation

**Solution**: Add Python to PATH manually

1. Press `Win + X` → Choose "System"
2. Click "Advanced system settings"
3. Click "Environment Variables" button
4. Under "System variables", find "Path" and click "Edit"
5. Click "New" and add:
   ```
   C:\Users\<YourUsername>\AppData\Local\Programs\Python\Python311
   ```
   Or if installed in Program Files:
   ```
   C:\Program Files\Python311
   ```
6. Click "OK" three times
7. **Close all open terminals and open a new one**
8. Try `python --version` again

### "pip not found"

Usually means Python installation is incomplete:
```powershell
python -m pip install --upgrade pip
```

### Can't create .venv

Make sure PowerShell is running from the correct directory:
```powershell
cd "E:\web peojects\cyber secruty (security+)"
python -m venv .venv
```

---

## File Structure Ready For You

Once Python is installed, these files are ready to use:

| File | Purpose |
|------|---------|
| `QUICK_START.bat` | 5-minute setup for SQLite (easiest) |
| `run.bat` | Launch backend with .env config |
| `launch_backend.ps1` | Advanced launcher with diagnostics |
| `SETUP_POSTGRESQL.ps1` | Full PostgreSQL setup |
| `verify_database.py` | Check database connection |

---

## Installation Checklist

### Before Starting
- [ ] Python 3.11+ downloaded
- [ ] "Add Python to PATH" checkbox will be checked

### Python Installation
- [ ] Run Python installer
- [ ] ✓ **CHECK** "Add Python 3.x to PATH"
- [ ] Click "Install Now"
- [ ] Wait for completion
- [ ] Verify: `python --version` returns version number

### PostgreSQL (Optional)
- [ ] PostgreSQL 15 downloaded (optional)
- [ ] PostgreSQL installed and running
- [ ] Service started (Services.msc → PostgreSQL → Started)

### Project Setup
- [ ] Close all terminals
- [ ] Open new PowerShell window
- [ ] Navigate to project: `cd "E:\web peojects\cyber secruty (security+)"`
- [ ] Run: `.\QUICK_START.bat`
- [ ] Wait 5-10 minutes for setup
- [ ] Open API docs: http://127.0.0.1:8000/docs

---

## What Happens When You Run QUICK_START.bat

```
QUICK_START.bat
    ↓
Checks Python installation
    ↓
Creates .venv (virtual environment)
    ↓
Installs 17 packages (FastAPI, SQLAlchemy, etc.)
    ↓
Creates .env configuration file
    ↓
Initializes SQLite database
    ↓
Launches FastAPI server on port 8000
    ↓
Opens http://127.0.0.1:8000/docs in browser
    ↓
✓ Ready to test API!
```

---

## Success Indicators

When everything works, you'll see:

```
 [OK] Python found
 [OK] Virtual environment created
 [OK] Dependencies installed
 [OK] .env configuration created
 [OK] Database schema initialized

====================================================================
   SETUP COMPLETE - Starting Backend Server
====================================================================

API Documentation: http://127.0.0.1:8000/docs
ReDoc: http://127.0.0.1:8000/redoc

[INFO] Opening API documentation in browser...
[INFO] Starting FastAPI server...
Press Ctrl+C to stop
```

And the browser opens showing: **Swagger UI - API Documentation**

---

## Next Steps

1. **Install Python 3.11+ first** - Make sure to check "Add Python to PATH"
2. **Close and reopen terminal** - So Python is in PATH
3. **Run QUICK_START.bat** - Fully automated setup
4. **Access API at http://127.0.0.1:8000/docs**

---

## Questions?

See the complete guide: `SETUP_AND_LAUNCH_GUIDE.md`

PostgreSQL setup guide: `POSTGRESQL_INSTALLATION.md`

---

**Status**: Awaiting Python 3.11+ Installation  
**Estimated Time**: 10 minutes installation + 5 minutes setup = 15 minutes total
