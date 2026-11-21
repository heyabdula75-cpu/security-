"""
Base SQLAlchemy model configuration.
Includes SQLite compatibility compiler for PostgreSQL UUID columns so local dev
and in-memory test suites work seamlessly alongside PostgreSQL in production.
"""
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import declarative_base


@compiles(PG_UUID, "sqlite")
def _compile_pg_uuid_sqlite(type_, compiler, **kw):
    return "CHAR(36)"


Base = declarative_base()
