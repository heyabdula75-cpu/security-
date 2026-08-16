"""
Configuration settings for the FastAPI application
"""
import os
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    APP_NAME: str = "SBOM Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    # PostgreSQL is the primary database for this platform.
    # Override via environment variable if you want a different host or credentials.
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/sbom_platform",
    )
    DATABASE_ECHO: bool = False
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800
    DB_CONNECT_TIMEOUT: int = 10
    DB_SSL_MODE: str = "disable"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security
    SECRET_KEY: str = os.getenv("JWT_SECRET", "your-secret-key-here-change-in-production")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # API
    API_URL: str = "http://localhost:8000"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",  # Frontend dev server
        "http://localhost:3000",  # Alternative frontend
        "https://localhost",
    ]
    
    # External APIs
    GITHUB_API_KEY: str = ""
    NVD_API_KEY: str = ""
    OSS_INDEX_USERNAME: str = ""
    OSS_INDEX_PASSWORD: str = ""
    
    # Features
    ENABLE_MFA: bool = False
    ENABLE_WEBHOOKS: bool = True
    ENABLE_ASYNC_PROCESSING: bool = True

    @field_validator("DEBUG", "DATABASE_ECHO", "ENABLE_MFA", "ENABLE_WEBHOOKS", "ENABLE_ASYNC_PROCESSING", mode="before")
    @classmethod
    def parse_bool_strings(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "released", "prod", "production", "off", "disabled"}:
                return False
            if normalized in {"dev", "development", "on", "enabled"}:
                return True
        return value
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
    }

@lru_cache()
def get_settings():
    """Get cached settings instance"""
    return Settings()

settings = get_settings()
