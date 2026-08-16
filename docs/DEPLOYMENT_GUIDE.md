# SecureChain — Complete Deployment Guide

> Enterprise-grade SBOM generation, vulnerability scanning, and AI-powered threat detection

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Development Setup](#development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Database Configuration](#database-configuration)
6. [Security Considerations](#security-considerations)
7. [Monitoring & Troubleshooting](#monitoring--troubleshooting)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 20+ (optional, for frontend development)
- Docker & Docker Compose (for containerized deployment)
- Git

### Local Development (2 terminals)

**Terminal 1 — Backend:**
```bash
cd src/backend
python -m venv ../.venv
.\.venv\Scripts\activate        # Windows
source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd frontend
python -m http.server 5173      # or use Node dev server
# Then open http://127.0.0.1:5173
```

**Backend API:** http://127.0.0.1:8000
- **Swagger UI:** http://127.0.0.1:8000/docs
- **ReDoc:** http://127.0.0.1:8000/redoc
- **OpenAPI Spec:** http://127.0.0.1:8000/openapi.json

---

## 💻 Development Setup

### Environment Configuration

Create `.env` file in `src/backend/`:

```env
# Database
DATABASE_URL=sqlite+aiosqlite:///./sbom_platform.db
DATABASE_ECHO=False

# Security
DEBUG=True
SECRET_KEY=dev-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# CORS
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000","http://127.0.0.1:5173"]

# Features
ENABLE_MFA=False
ENABLE_WEBHOOKS=True
ENABLE_ASYNC_PROCESSING=True
```

### Running Tests

```bash
cd src/backend

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_auth.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html
```

### Database Initialization

The database is automatically initialized on first startup. To reset:

```bash
cd src/backend
rm sbom_platform.db              # Remove SQLite file
# Restart backend — new database will be created
```

---

## 🐳 Docker Deployment

### Development with Docker

```bash
# Build and start services
docker-compose -f docker-compose.dev.yml up --build

# Stop services
docker-compose -f docker-compose.dev.yml down

# View logs
docker-compose -f docker-compose.dev.yml logs -f backend
docker-compose -f docker-compose.dev.yml logs -f frontend
```

**Access:** http://localhost:5173

### Production with Docker

```bash
# Set environment variables
export POSTGRES_USER=sbom_admin
export POSTGRES_PASSWORD=secure-password-here
export SECRET_KEY=$(openssl rand -hex 32)

# Start production stack
docker-compose -f docker-compose.prod.yml up -d

# View status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f backend
docker-compose -f docker-compose.prod.yml logs -f frontend
```

**Access:** 
- Frontend: http://localhost (or your domain)
- API Docs: http://localhost/docs
- ReDoc: http://localhost/redoc

---

## 🗄️ Database Configuration

### SQLite (Development — Default)

- **File-based storage** — no server required
- **Location:** `src/backend/sbom_platform.db`
- **URL:** `sqlite+aiosqlite:///./sbom_platform.db`
- **Best for:** Local development, rapid prototyping

### PostgreSQL (Production — Recommended)

- **Enterprise-grade** — ACID compliance, advanced features
- **Setup:**
  ```bash
  # Install PostgreSQL
  # Ubuntu/Debian
  sudo apt-get install postgresql postgresql-contrib
  
  # macOS
  brew install postgresql
  
  # Create database
  createdb sbom_platform
  createuser sbom_admin
  ```

- **Connection String:**
  ```
  postgresql+asyncpg://sbom_admin:password@localhost:5432/sbom_platform
  ```

- **Set in `.env`:**
  ```env
  DATABASE_URL=postgresql+asyncpg://sbom_admin:password@localhost:5432/sbom_platform
  ```

### Database Migrations

Use Alembic for schema changes:

```bash
cd src/backend

# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

---

## 🔐 Security Considerations

### API Authentication

All endpoints (except `/health`) require JWT authentication:

```bash
# 1. Register user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "full_name": "John Doe"
  }'

# 2. Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'

# Response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "bearer",
#   "expires_in": 3600
# }

# 3. Use token in Authorization header
curl -X GET "http://localhost:8000/api/v1/auth/profile" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### HTTPS in Production

1. **Obtain SSL certificate** (Let's Encrypt recommended):
   ```bash
   certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
   ```

2. **Configure Nginx** (`deployment/nginx/default.conf`):
   ```nginx
   server {
       listen 443 ssl http2;
       ssl_certificate /etc/nginx/ssl/cert.pem;
       ssl_certificate_key /etc/nginx/ssl/key.pem;
       # ... rest of config
   }
   ```

3. **Set environment variables:**
   ```bash
   CORS_ORIGINS=["https://yourdomain.com","https://app.yourdomain.com"]
   ```

### Secret Management

- **Development:** Store in `.env` file (never commit)
- **Production:** Use:
  - Docker secrets
  - Environment variables (via CI/CD or secrets manager)
  - AWS Secrets Manager / HashiCorp Vault
  - Kubernetes secrets

**Never hardcode secrets in code!**

---

## 📊 Monitoring & Troubleshooting

### Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Response: {"status": "ok", "db": "connected"}
```

### View Docker Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend

# With timestamps
docker-compose logs -f --timestamps
```

### Common Issues

#### 1. **Backend refuses connection**
```bash
# Check if port 8000 is already in use
lsof -i :8000              # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Kill process on port 8000
kill -9 <PID>              # macOS/Linux
taskkill /PID <PID> /F     # Windows
```

#### 2. **Database connection error**
```bash
# Check environment variable
echo $DATABASE_URL

# Verify database exists and is accessible
psql -U sbom_admin -d sbom_platform -h localhost -c "SELECT 1"
```

#### 3. **Frontend can't connect to API**
- Check backend is running: `curl http://127.0.0.1:8000/health`
- Check CORS_ORIGINS includes frontend URL
- Check browser console for error messages (F12)
- Verify frontend uses correct API endpoint in `app.js`

#### 4. **Permission denied errors in Docker**
```bash
# Run with appropriate permissions
sudo docker-compose up
# Or add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

---

## 📈 Performance Optimization

### Caching Strategy

Configure Redis in production:

```env
REDIS_URL=redis://redis:6379/0
```

### Database Optimization

```python
# Backend: use async database queries
async with get_session() as session:
    result = await session.execute(select(Project))
    projects = result.scalars().all()
```

### Frontend Optimization

- Enable gzip compression (configured in nginx)
- Cache static assets (30-day expiry set in nginx)
- Minify JavaScript and CSS in production build
- Use CDN for content delivery

---

## 🚢 Deployment Checklist

- [ ] Environment variables set for production
- [ ] SECRET_KEY changed from default
- [ ] Database backups configured
- [ ] HTTPS/SSL certificates installed
- [ ] CORS origins updated to production domains
- [ ] Health checks passing for all services
- [ ] Logs being collected and monitored
- [ ] Rate limiting configured
- [ ] API documentation reviewed
- [ ] Load testing completed

---

## 📚 Additional Resources

- **FastAPI Docs:** https://fastapi.tiangolo.com/
- **SQLAlchemy Docs:** https://docs.sqlalchemy.org/
- **Docker Docs:** https://docs.docker.com/
- **Nginx Docs:** https://nginx.org/en/docs/
- **PostgreSQL Docs:** https://www.postgresql.org/docs/

---

**Last Updated:** 2025-01-15  
**Maintained By:** Security Engineering Team  
**Version:** 1.0.0
