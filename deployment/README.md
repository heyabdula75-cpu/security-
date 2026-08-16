# 🚀 Deployment Scripts & Configuration

This directory contains all deployment and orchestration configurations for the SecureChain platform.

## 📁 Structure

```
deployment/
├── SETUP_DEV.bat                 # Quick local development setup
├── START_DOCKER_DEV.bat          # Start Docker development environment
├── DEPLOY_PRODUCTION.bat         # Deploy to production with Docker
├── HEALTH_CHECK.bat              # Monitor system health
├── nginx/
│   ├── nginx.conf                # Nginx main configuration
│   ├── default.conf              # Nginx site configuration
│   └── ssl/                      # SSL certificates (production)
└── README.md                      # This file
```

---

## 🎯 Quick Start

### Option 1: Local Development (Fastest)
```bash
deployment/SETUP_DEV.bat
# Then run in 2 terminals:
# Terminal 1: cd src/backend && uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
# Terminal 2: cd frontend && python -m http.server 5173
```

### Option 2: Docker Development
```bash
deployment/START_DOCKER_DEV.bat
# Opens at http://localhost:5173
```

### Option 3: Production Deployment
```bash
deployment/DEPLOY_PRODUCTION.bat
# Automated production setup with PostgreSQL, Redis, etc.
```

---

## 📜 Available Scripts

### SETUP_DEV.bat
**Purpose:** Initialize local development environment

**What it does:**
- Creates Python virtual environment
- Installs dependencies from `requirements.txt`
- Creates development `.env` file
- Configures SQLite database

**Usage:**
```bash
cd <project-root>
deployment/SETUP_DEV.bat
```

**Output:**
```
✅ Virtual environment created
✅ Dependencies installed
✅ Created .env
🌐 Frontend:  http://127.0.0.1:5173
📖 API Docs:  http://127.0.0.1:8000/docs
```

---

### START_DOCKER_DEV.bat
**Purpose:** Run complete development stack in Docker

**Prerequisites:**
- Docker Desktop installed and running
- Docker Compose (built-in with Docker Desktop)

**What it does:**
- Builds Docker images for backend and frontend
- Starts both services with volume mounting for live reload
- Exposes ports 5173 (frontend) and 8000 (backend)

**Usage:**
```bash
deployment/START_DOCKER_DEV.bat
```

**Access:**
```
Frontend:    http://localhost:5173
API Docs:    http://localhost:8000/docs
```

**To stop:** Press `Ctrl+C` in the terminal

---

### DEPLOY_PRODUCTION.bat
**Purpose:** Deploy production-ready stack with PostgreSQL, Redis, and Nginx

**Prerequisites:**
- Docker Desktop installed
- 4+ GB available disk space
- Domain name (for production use)

**What it does:**
1. Prompts for PostgreSQL password (16+ chars recommended)
2. Auto-generates strong `SECRET_KEY`
3. Prompts for domain name
4. Creates `.env.prod` with secure settings
5. Builds Docker images with optimizations
6. Starts PostgreSQL, Redis, backend, and frontend
7. Configures Nginx reverse proxy

**Usage:**
```bash
deployment/DEPLOY_PRODUCTION.bat
```

**Configuration Prompts:**
```
Enter PostgreSQL password (min 16 chars): MySecurePassword123!
Enter domain name (e.g., yourdomain.com): app.example.com
```

**Access After Deployment:**
```
Frontend:    http://app.example.com
API Docs:    http://app.example.com/docs
Backend API: http://app.example.com/api/v1
```

**Services Started:**
- PostgreSQL (port 5432, internal only)
- Redis (port 6379, internal only)
- Backend (port 8000, proxied by Nginx)
- Frontend (port 5173, proxied by Nginx)
- Nginx (ports 80/443)

---

### HEALTH_CHECK.bat
**Purpose:** Monitor system health and diagnose issues

**What it does:**
- Checks if backend is responding
- Checks if frontend is responding
- Checks API documentation availability
- Verifies database file exists
- Checks port availability
- Generates system status report

**Usage:**
```bash
deployment/HEALTH_CHECK.bat
```

**Sample Output:**
```
✅ Backend running at http://127.0.0.1:8000
✅ Frontend running at http://127.0.0.1:5173
✅ API Swagger UI available at http://127.0.0.1:8000/docs
✅ SQLite database found (approx 2.5MB)
✅ Port 8000 is in use
```

---

## 🐳 Docker Compose Files

### docker-compose.dev.yml
**Purpose:** Local development with Docker

**Services:**
- Backend (FastAPI, port 8000)
- Frontend (Nginx, port 5173)

**Features:**
- Volume mounting for live reload
- SQLite database
- Network isolation

**Usage:**
```bash
docker-compose -f docker-compose.dev.yml up --build
docker-compose -f docker-compose.dev.yml down
docker-compose -f docker-compose.dev.yml logs -f backend
```

### docker-compose.prod.yml
**Purpose:** Production-ready deployment

**Services:**
- PostgreSQL (port 5432, internal)
- Redis (port 6379, internal)
- Backend (port 8000, proxied)
- Frontend (ports 80/443)
- Nginx reverse proxy

**Features:**
- Persistent volumes for data
- Health checks for all services
- SSL/TLS ready
- Auto-restart on failure
- Optimized images

**Usage:**
```bash
# Start
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Stop
docker-compose -f docker-compose.prod.yml down
```

---

## 🔒 Nginx Configuration

### nginx/nginx.conf
**Main configuration file** with:
- Worker process optimization
- Gzip compression
- File upload limits (100MB)
- Security headers

### nginx/default.conf
**Site configuration** with:
- SSL/TLS support (ready for certificates)
- API reverse proxy to backend
- Static asset caching (30 days)
- Security headers (X-Frame-Options, CSP, etc.)
- Health check endpoints

**Features:**
- Automatic GZIP compression
- Browser caching for static assets
- API documentation proxying
- WebSocket support

---

## 🔐 Environment Configuration

### Development (.env)
```env
DATABASE_URL=sqlite+aiosqlite:///./sbom_platform.db
DEBUG=True
SECRET_KEY=dev-secret-key-change-in-production
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]
```

### Production (.env.prod - Auto-generated)
```env
POSTGRES_USER=sbom_admin
POSTGRES_PASSWORD=<auto-generated-secure-password>
SECRET_KEY=<auto-generated-32-char-hex>
DATABASE_URL=postgresql+asyncpg://sbom_admin:password@postgres:5432/sbom_platform
CORS_ORIGINS=["https://yourdomain.com"]
```

---

## 🆘 Troubleshooting

### Docker issues
```bash
# Check Docker status
docker ps
docker ps -a  # including stopped containers

# View service logs
docker-compose logs -f <service-name>

# Rebuild images
docker-compose build --no-cache

# Remove all images and start fresh
docker-compose down -v
docker-compose up --build
```

### Port conflicts
```bash
# Windows: Find process using port
netstat -ano | findstr :8000

# Kill process
taskkill /PID <PID> /F

# macOS/Linux
lsof -i :8000
kill -9 <PID>
```

### Database issues
```bash
# Reset development database
rm src/backend/sbom_platform.db
# Restart backend to recreate

# Check PostgreSQL (production)
docker exec sbom-postgres-prod psql -U sbom_admin -d sbom_platform -c "SELECT 1"
```

---

## 📈 Performance Tuning

### For Development
- Use SQLite (fast, no setup)
- Enable DEBUG mode
- Use auto-reload

### For Production
- Use PostgreSQL (enterprise features)
- Disable DEBUG mode
- Enable Redis caching
- Configure CDN for static assets
- Use SSL/TLS
- Set up monitoring and logging

---

## 🔄 Common Workflows

### Update Backend Code
```bash
# If using Docker, changes reload automatically
# If local, restart uvicorn (Ctrl+C, then re-run command)

# If using Docker and need to rebuild:
docker-compose build backend
docker-compose up backend
```

### Deploy New Version
```bash
# Pull latest code
git pull origin main

# Rebuild Docker images
docker-compose -f docker-compose.prod.yml build

# Restart services
docker-compose -f docker-compose.prod.yml restart
```

### View Database
```bash
# SQLite (development)
sqlite3 src/backend/sbom_platform.db
> SELECT * FROM user;

# PostgreSQL (production)
docker exec sbom-postgres-prod psql -U sbom_admin -d sbom_platform
> SELECT * FROM "user";
```

---

## 📚 Additional Resources

- **Deployment Guide:** See `docs/DEPLOYMENT_GUIDE.md`
- **Status Report:** See `docs/DEPLOYMENT_STATUS.md`
- **API Documentation:** Start backend and visit http://127.0.0.1:8000/docs
- **Architecture:** See `docs/PHASE2_SYSTEM_ARCHITECTURE.md`

---

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review logs: `docker-compose logs -f`
3. Run health check: `deployment/HEALTH_CHECK.bat`
4. Consult documentation in `/docs/`

---

**Last Updated:** 2025-01-15  
**Version:** 1.0.0  
**Maintained By:** Security Engineering Team
