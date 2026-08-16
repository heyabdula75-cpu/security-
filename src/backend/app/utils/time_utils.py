"""Helpers for consistent UTC timestamps."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return a timezone-aware UTC datetime without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def utcnow_iso() -> str:
    """Return a UTC timestamp in ISO 8601 format with a trailing Z."""
    return utcnow().isoformat().replace("+00:00", "Z")
