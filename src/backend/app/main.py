"""
FastAPI Application Main Entry Point
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.db_init import get_database_readiness, initialize_database_from_settings
from app.middleware.security import EnterpriseSecurityMiddleware
from app.services.platform_ops_service import render_prometheus_metrics
from app.api.v1.auth import router as auth_router
from app.api.v1.projects import router as projects_router
from app.api.v1.sboms import router as sboms_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.risks import router as risks_router
from app.api.v1.threats import router as threats_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.vex import router as vex_router
from app.api.v1.enterprise import router as enterprise_router
from app.api.v1.integrations import router as integrations_router

logger = logging.getLogger("app.startup")

# Resolve the frontend directory: app/main.py → app/ → backend/ → src/ → project root → frontend/
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB and sync live CISA KEV catalog in background."""
    try:
        await initialize_database_from_settings()
        logger.info("Database schema initialization completed")
    except Exception as exc:
        logger.warning("Database schema initialization skipped: %s", exc)

    async def _bg_kev_sync():
        try:
            from app.services.feed_sync_service import sync_cisa_kev_catalog
            res = await sync_cisa_kev_catalog(timeout=5.0)
            logger.info("Live CISA KEV feed sync: %s (%s CVEs)", res.get("status"), res.get("total_kev_cves"))
        except Exception as exc:
            logger.debug("Background KEV sync skipped: %s", exc)

    bg_task = asyncio.create_task(_bg_kev_sync())
    yield
    if not bg_task.done():
        bg_task.cancel()


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
app.add_middleware(EnterpriseSecurityMiddleware, requests_per_minute=300)

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

@app.get("/metrics", tags=["Observability"], response_class=PlainTextResponse)
async def prometheus_metrics(db: AsyncSession = Depends(get_db)):
    """Prometheus metrics endpoint for enterprise observability."""
    return PlainTextResponse(content=await render_prometheus_metrics(db), media_type="text/plain; version=0.0.4")


# Include routers
app.include_router(auth_router, prefix="/api/v1", tags=["Authentication"])
app.include_router(projects_router, prefix="/api/v1", tags=["Projects"])
app.include_router(sboms_router, prefix="/api/v1", tags=["SBOMs"])
app.include_router(vulnerabilities_router, prefix="/api/v1", tags=["Vulnerabilities"])
app.include_router(risks_router, prefix="/api/v1", tags=["Risk Scoring"])
app.include_router(threats_router, prefix="/api/v1", tags=["Threats"])
app.include_router(compliance_router, prefix="/api/v1", tags=["Compliance"])
app.include_router(vex_router, prefix="/api/v1", tags=["VEX & Reachability"])
app.include_router(enterprise_router, prefix="/api/v1", tags=["AI Copilot, Signing & Enterprise"])
app.include_router(integrations_router, prefix="/api/v1", tags=["Integrations, Feeds & SSO"])

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
