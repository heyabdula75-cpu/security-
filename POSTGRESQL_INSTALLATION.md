# PostgreSQL Installation - Quick Start Guide
## For SecureChain Platform

**Status**: PostgreSQL NOT YET INSTALLED  
**Required**: PostgreSQL 14+ (15+ recommended)  
**Estimated Time**: 10-15 minutes

---

## Installation Steps

### Step 1: Download PostgreSQL
1. Open browser and go to: https://www.postgresql.org/download/windows/
2. Click the "Download the installer" link for **PostgreSQL 15**
3. The installer will be downloaded (EDB PostgreSQL 15.x installer)

### Step 2: Run the Installer
1. Double-click `postgresql-15.x-x64-setup.exe`
2. Click "Next" at the welcome screen
3. **Installation Directory**: Leave as default `C:\Program Files\PostgreSQL\15`
4. **Select Components**:
   - ✓ PostgreSQL Server
   - ✓ pgAdmin 4
   - ✓ Stack Builder
   - ✓ Command Line Tools
5. **Data Directory**: Leave as default `C:\Program Files\PostgreSQL\15\data`
6. **Password**: Enter a password for the `postgres` user
   - **IMPORTANT**: Write this down!
   - Example: `PostgresAdmin123!`
7. **Port**: Leave as default **5432**
8. **Locale**: Leave as default `[Default locale]`
9. Click "Next" to proceed with installation
10. Click "Finish" to complete installation
11. **Installation Complete**: The installer will ask about Stack Builder
    - Click "Finish" (Stack Builder is optional)

### Step 3: Verify Installation
Open PowerShell and run:
```powershell
psql --version
```

You should see: `psql (PostgreSQL) 15.x`

If not, add PostgreSQL to PATH:
```powershell
$env:PATH += ";C:\Program Files\PostgreSQL\15\bin"
```

### Step 4: Start PostgreSQL Service
```powershell
# Start PostgreSQL service
net start PostgreSQL15

# Or via Services:
# Press Win+R → type "services.msc" → find PostgreSQL15 → Right-click → Start
```

### Step 5: Test Connection
```powershell
# Connect to PostgreSQL
psql -U postgres -h 127.0.0.1

# Enter password when prompted (what you set in Step 2)
# You should see the psql prompt: postgres=#

# Type to exit:
\q
```

---

## After PostgreSQL is Installed

Once PostgreSQL is running, execute the automated setup:

```powershell
# Open PowerShell as Administrator
cd "E:\web peojects\cyber secruty (security+)"

# Run the comprehensive setup
PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
```

This will automatically:
- ✓ Create database: `sbom_platform`
- ✓ Create user: `sbom_user`
- ✓ Create Python virtual environment
- ✓ Install all dependencies
- ✓ Initialize database schema
- ✓ Create .env configuration file

---

## Troubleshooting PostgreSQL Installation

### PostgreSQL Service Won't Start
```powershell
# Check service status
Get-Service PostgreSQL15

# Manually start it
net start PostgreSQL15

# Check PostgreSQL is listening on port 5432
netstat -ano | findstr :5432
```

### psql Command Not Found
PostgreSQL needs to be added to your PATH:
```powershell
# Temporary (current session only)
$env:PATH += ";C:\Program Files\PostgreSQL\15\bin"

# Permanent (add to system PATH)
# Win+X → System → Advanced system settings → Environment Variables
# Add: C:\Program Files\PostgreSQL\15\bin
```

### Can't Connect to PostgreSQL
```powershell
# Verify connection
psql -U postgres -h 127.0.0.1

# If password fails, reset it:
# 1. Stop PostgreSQL service
net stop PostgreSQL15

# 2. Edit: C:\Program Files\PostgreSQL\15\data\pg_hba.conf
#    Change: md5 → trust (for local connections only)

# 3. Start PostgreSQL service
net start PostgreSQL15

# 4. Connect and reset password:
psql -U postgres -h 127.0.0.1
postgres=# ALTER USER postgres WITH PASSWORD 'NewPassword123!';
postgres=# \q

# 5. Revert pg_hba.conf back to md5
# 6. Restart PostgreSQL service
net stop PostgreSQL15
net start PostgreSQL15
```

### pgAdmin (Optional)
If you installed pgAdmin, you can manage databases graphically:
1. Open pgAdmin: http://127.0.0.1:5050
2. Connect to your PostgreSQL server
3. Create database and user through the GUI

---

## What's Next?

Once PostgreSQL is installed and running:

1. Close this guide
2. Run the automated setup:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File SETUP_POSTGRESQL.ps1
   ```
3. Wait for completion (5-10 minutes)
4. Launch the backend:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File launch_backend.ps1
   ```
5. Open API documentation: http://127.0.0.1:8000/docs

---

## Alternative: Use Docker PostgreSQL

If you prefer not to install PostgreSQL locally, you can use Docker:

```powershell
# Install Docker Desktop from https://www.docker.com/products/docker-desktop

# Run PostgreSQL in Docker
docker run --name sbom-postgres `
  -e POSTGRES_DB=sbom_platform `
  -e POSTGRES_USER=sbom_user `
  -e POSTGRES_PASSWORD=SecurePass123! `
  -p 5432:5432 `
  -d postgres:15

# Verify connection
psql -U sbom_user -h 127.0.0.1 -d sbom_platform
```

---

**After PostgreSQL is installed, proceed with running SETUP_POSTGRESQL.ps1**
