"""Temporal and Causality Management Module.

Enforces strict temporal cutoff invariants: evidence and activity records
are only admissible if their timestamps are less than or equal to audit_at.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional


def parse_iso_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parses an ISO-8601 formatted timestamp string into an offset-aware datetime in UTC."""
    if not ts_str:
        return None
    cleaned = ts_str.strip()
    if not cleaned:
        return None

    # Handle standard trailing 'Z'
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def is_admissible(record_timestamp: Optional[str], cutoff_timestamp: str) -> bool:
    """Returns True if record_timestamp <= cutoff_timestamp in UTC."""
    dt_record = parse_iso_datetime(record_timestamp)
    dt_cutoff = parse_iso_datetime(cutoff_timestamp)

    if dt_record is None or dt_cutoff is None:
        return False

    return dt_record <= dt_cutoff
