"""
FastAPI Application Main Entry Point
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db_init import get_database_readiness, initialize_database_from_settings
from app.api.v1.auth import router as auth_router
from app.api.v1.projects import router as projects_router
from app.api.v1.sboms import router as sboms_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.risks import router as risks_router
from app.api.v1.threats import router as threats_router
from app.api.v1.compliance import router as compliance_router

logger = logging.getLogger("app.startup")

# Resolve the frontend directory: app/main.py → app/ → backend/ → src/ → project root → frontend/
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB on startup."""
    try:
        await initialize_database_from_settings()
        logger.info("Database schema initialization completed")
    except Exception as exc:
        logger.warning("Database schema initialization skipped: %s", exc)
    yield


# Initialize FastAPI app
app = FastAPI(
    title="AI Supply Chain Security & SBOM Verification Platform",
    description="Enterprise-grade SBOM generation, vulnerability scanning, and threat detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring and load balancers."""
    readiness = await get_database_readiness()
    return {
        "status": "healthy" if readiness["status"] == "ready" else "degraded",
        "version": "1.0.0",
        "database": readiness,
    }

# Include routers
app.include_router(auth_router, prefix="/api/v1", tags=["Authentication"])
app.include_router(projects_router, prefix="/api/v1", tags=["Projects"])
app.include_router(sboms_router, prefix="/api/v1", tags=["SBOMs"])
app.include_router(vulnerabilities_router, prefix="/api/v1", tags=["Vulnerabilities"])
app.include_router(risks_router, prefix="/api/v1", tags=["Risk Scoring"])
app.include_router(threats_router, prefix="/api/v1", tags=["Threats"])
app.include_router(compliance_router, prefix="/api/v1", tags=["Compliance"])

@app.get("/api", tags=["Root"])
async def api_root():
    """API information endpoint"""
    return {
        "message": "AI Supply Chain Security Platform API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc",
    }

# Mount frontend static files LAST so the API routes take priority.
# Only mount if the frontend directory actually exists.
if _FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
    logger.info("Frontend static files mounted from: %s", _FRONTEND_DIR)
else:
    logger.warning("Frontend directory not found at %s — UI will not be served.", _FRONTEND_DIR)

    @app.get("/", tags=["Root"])
    async def root():
        """Fallback root when no frontend is built."""
        return {
            "message": "AI Supply Chain Security Platform API",
            "version": "1.0.0",
            "docs": "/docs",
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
