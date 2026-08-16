# ============================================================================
# Database Connection Verification Script
# AI Supply Chain Security & SBOM Verification Platform
# ============================================================================
# Verifies PostgreSQL connection and database schema

import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add backend to path
backend_dir = Path(__file__).parent / "src" / "backend"
sys.path.insert(0, str(backend_dir))

from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import create_async_engine
from app.config import settings


async def verify_database_connection():
    """Verify PostgreSQL connection and database schema."""
    
    print("\n" + "=" * 70)
    print("PostgreSQL Database Verification")
    print("=" * 70 + "\n")
    
    db_url = settings.DATABASE_URL
    print(f"✓ Loading database URL from configuration")
    print(f"  Database URL: {db_url[:50]}...***\n")
    
    # Parse connection details
    parsed = urlparse(db_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 5432
    database = parsed.path.lstrip("/")
    
    print(f"Connection Details:")
    print(f"  Host:     {host}")
    print(f"  Port:     {port}")
    print(f"  Database: {database}")
    print(f"  User:     {parsed.username}\n")
    
    # Test connection
    print("Attempting connection...")
    try:
        engine = create_async_engine(db_url, echo=False, future=True)
        
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version();"))
            version = result.scalar()
            print(f"✓ PostgreSQL connected successfully!")
            print(f"  Version: {version}\n")
        
        # Verify tables exist
        print("Verifying database schema...")
        async with engine.begin() as conn:
            inspector = inspect(engine.sync_engine)
            tables = inspector.get_table_names()
            
            if tables:
                print(f"✓ Found {len(tables)} tables:\n")
                for table in sorted(tables):
                    print(f"  • {table}")
                print()
            else:
                print("⚠ No tables found - database schema not initialized")
                print("  Run: python -c \"import asyncio; from app.db_init import initialize_database_from_settings; asyncio.run(initialize_database_from_settings())\"\n")
        
        await engine.dispose()
        print("✓ Database verification completed successfully!\n")
        return True
        
    except Exception as e:
        print(f"✗ Database connection failed!")
        print(f"  Error: {e}\n")
        
        if "refused" in str(e):
            print("Troubleshooting:")
            print("  1. Verify PostgreSQL is running:")
            print("     Services.msc → PostgreSQL → Restart")
            print("  2. Verify database exists:")
            print("     psql -U postgres -h 127.0.0.1 -l")
            print("  3. Check connection credentials in .env\n")
        
        return False


async def main():
    """Main entry point."""
    success = await verify_database_connection()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
