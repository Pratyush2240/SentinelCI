"""
audit_service/main.py

SentinelCI Audit Service — FastAPI application for persisting and querying
security scan findings.

Run locally:
    uvicorn audit_service.main:app --reload
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

load_dotenv(Path(__file__).parent / ".env")

# ---------------------------------------------------------------------------
# Auth — API key is MVP-only auth; production path is GitHub OIDC.
# ---------------------------------------------------------------------------
_API_KEY: str = os.environ.get("SENTINELCI_AUDIT_API_KEY", "")
if not _API_KEY:
    raise RuntimeError(
        "SENTINELCI_AUDIT_API_KEY environment variable is required but not set. "
        "The audit service refuses to start unauthenticated. "
        "See audit_service/.env.example."
    )


def _require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Dependency that validates the X-API-Key header on protected endpoints."""
    if not x_api_key or not secrets.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# App & DB
# ---------------------------------------------------------------------------
app = FastAPI(title="SentinelCI Audit Service", version="0.1.0")

# Import pool lazily so the module-level schema bootstrap in db.py runs at
# import time (after dotenv has loaded DATABASE_URL above).
from audit_service.db import pool  # noqa: E402


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class FindingCreate(BaseModel):
    """Request body for POST /findings — matches findings table columns
    (excluding server-managed fields: id, status, override_*, timestamps)."""

    repo: str
    pr_number: int
    commit_sha: str
    file_path: str
    line: Optional[int] = None
    rule_id: str
    code_hash: str
    severity: str
    confidence: Optional[str] = None
    category: Optional[str] = None
    action: str
    reasoning: Optional[str] = None
    override_eligible: bool = False


class FindingUpsertResponse(BaseModel):
    id: int
    status: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    """Liveness probe — no auth, no DB call."""
    return {"status": "ok"}


@app.post("/findings", response_model=FindingUpsertResponse, dependencies=[Depends(_require_api_key)])
def create_finding(
    body: FindingCreate,
) -> FindingUpsertResponse:
    """Upsert a finding.

    INSERT ... ON CONFLICT (dedupe key) DO UPDATE refreshes mutable assessment
    fields and last_seen_at, but NEVER touches status or override_* columns —
    this is deliberate: an existing override must survive a re-scan.
    """
    sql = """
        INSERT INTO findings (
            repo, pr_number, commit_sha,
            file_path, line, rule_id, code_hash,
            severity, confidence, category, action, reasoning,
            override_eligible
        ) VALUES (
            %(repo)s, %(pr_number)s, %(commit_sha)s,
            %(file_path)s, %(line)s, %(rule_id)s, %(code_hash)s,
            %(severity)s, %(confidence)s, %(category)s, %(action)s, %(reasoning)s,
            %(override_eligible)s
        )
        ON CONFLICT (repo, pr_number, file_path, rule_id, code_hash)
        DO UPDATE SET
            commit_sha         = EXCLUDED.commit_sha,
            line               = EXCLUDED.line,
            severity           = EXCLUDED.severity,
            confidence         = EXCLUDED.confidence,
            category           = EXCLUDED.category,
            action             = EXCLUDED.action,
            reasoning          = EXCLUDED.reasoning,
            override_eligible  = EXCLUDED.override_eligible,
            last_seen_at       = now()
            -- NOTE: status, override_by, override_reason, override_at are
            -- intentionally NOT updated here.  An existing override must
            -- survive a re-scan (architecture.md §4).
        RETURNING id, status;
    """

    with pool.connection() as conn:
        row = conn.execute(sql, body.model_dump()).fetchone()
        conn.commit()

    assert row is not None  # RETURNING always produces a row on INSERT/UPDATE
    return FindingUpsertResponse(id=row[0], status=row[1])


@app.get("/findings/{finding_id}", dependencies=[Depends(_require_api_key)])
def get_finding(
    finding_id: int,
) -> dict:
    """Return the full finding row as JSON. 404 if missing.

    This is what Step 10's eligibility check will call.
    """
    sql = "SELECT * FROM findings WHERE id = %s;"

    with pool.connection() as conn:
        cur = conn.execute(sql, (finding_id,))
        row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    columns = [desc[0] for desc in cur.description]
    record = dict(zip(columns, row))

    # Serialize datetime fields to ISO strings for JSON compatibility
    for key in ("first_seen_at", "last_seen_at", "override_at"):
        if record.get(key) is not None:
            record[key] = record[key].isoformat()

    return record
