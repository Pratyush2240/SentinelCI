"""
audit_service/db.py

Database connection pool and schema bootstrap for the SentinelCI Audit Service.
Reads DATABASE_URL from the environment (python-dotenv for local .env).
Neon requires sslmode=require — this should already be in the connection string,
so we don't hardcode it here.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from psycopg_pool import ConnectionPool

load_dotenv(Path(__file__).parent / ".env")

DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required but not set. "
        "See audit_service/.env.example for the expected format."
    )

pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=10)

# ---------------------------------------------------------------------------
# Schema bootstrap — runs schema.sql once at import time so the table exists
# before the first request.  Safe to re-run (CREATE TABLE IF NOT EXISTS).
# ---------------------------------------------------------------------------
_schema_path = Path(__file__).with_name("schema.sql")
_schema_sql = _schema_path.read_text(encoding="utf-8")

with pool.connection() as conn:
    conn.execute(_schema_sql)
    conn.commit()
