"""
app/audit_client.py

Client adapter for the SentinelCI Audit Service (FastAPI + Postgres).
Persists findings to the central audit log for persistence across PR pushes
and slash-command overrides.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Optional

import requests


class AuditError(Exception):
    """Raised when an operation against the SentinelCI Audit Service fails."""
    pass


def compute_code_hash(code_text: str) -> str:
    """Compute sha256 hex of flagged code text with leading/trailing whitespace stripped per line.

    This is the dedupe key component that keeps a Finding ID stable across pushes
    (architecture.md §4 step 10). It must NOT include the line number so line shifts
    do not change the finding identity.
    """
    if not code_text or not code_text.strip():
        raise AuditError("Flagged code text is empty; cannot compute code_hash for audit logging.")
    if "requires login" in code_text:
        raise AuditError(
            "Flagged code text contains 'requires login' placeholder from unauthenticated Semgrep scan. "
            "Refusing to hash placeholder."
        )

    lines = [line.strip() for line in code_text.splitlines()]
    normalized = "\n".join(lines)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def log_finding(result: Any, repo: str, pr_number: int, commit_sha: str) -> int:
    """Log a finding record to the SentinelCI Audit Service via POST /findings.

    Parameters
    ----------
    result : dict or Finding
        The security finding assessment record.
    repo : str
        GitHub repository in 'owner/repo' format.
    pr_number : int
        Pull Request number.
    commit_sha : str
        Commit SHA for the scan run.

    Returns
    -------
    int
        The audit-assigned finding ID.
    """
    # Reads via os.environ[...] (KeyError on purpose if missing: fail loudly, no .get with empty default).
    audit_url = os.environ["SENTINELCI_AUDIT_URL"].rstrip("/")
    api_key = os.environ["SENTINELCI_AUDIT_API_KEY"]

    if isinstance(result, dict):
        file_path = result.get("file_path", "")
        line = result.get("start_line") if result.get("start_line") is not None else result.get("line")
        rule_id = result.get("rule_id", "")
        code_text = result.get("code") or ""
        code_hash = result.get("code_hash") or compute_code_hash(code_text)

        sev = result.get("severity", "")
        conf = result.get("confidence")
        cat = result.get("category")
        act = result.get("action", "")
        reasoning = result.get("reasoning")
        override_eligible = bool(result.get("override_eligible", False))
    else:
        file_path = getattr(result, "file_path", "") or getattr(getattr(result, "semgrep", None), "file_path", "")
        line = getattr(result, "start_line", None) or getattr(result, "line", None) or getattr(getattr(result, "semgrep", None), "start_line", None)
        rule_id = getattr(result, "rule_id", "") or getattr(getattr(result, "semgrep", None), "rule_id", "")
        code_text = getattr(result, "code", "") or getattr(getattr(result, "context", None), "flagged_code", "")
        code_hash = getattr(result, "code_hash", None) or compute_code_hash(code_text)

        sev = getattr(result, "severity", "")
        conf = getattr(result, "confidence", None)
        cat = getattr(result, "category", None)
        act = getattr(result, "action", "")
        reasoning = getattr(result, "reasoning", None)
        override_eligible = bool(getattr(result, "override_eligible", False))

    severity_str = sev.value if hasattr(sev, "value") else str(sev) if sev else "UNKNOWN"
    severity_str = severity_str.upper()

    action_str = act.value if hasattr(act, "value") else str(act) if act else "UNKNOWN"
    action_str = action_str.upper()

    confidence_str: Optional[str] = None
    if conf is not None:
        c_val = conf.value if hasattr(conf, "value") else str(conf)
        if c_val and c_val.upper() not in ("NONE", "NULL", "N/A"):
            confidence_str = c_val.upper()

    category_str: Optional[str] = cat if cat else None

    payload = {
        "repo": repo,
        "pr_number": int(pr_number),
        "commit_sha": commit_sha,
        "file_path": file_path,
        "line": int(line) if line is not None else None,
        "rule_id": rule_id,
        "code_hash": code_hash,
        "severity": severity_str,
        "confidence": confidence_str,
        "category": category_str,
        "action": action_str,
        "reasoning": reasoning,
        "override_eligible": override_eligible,
    }

    endpoint = f"{audit_url}/findings"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }

    # the one retry covers a cold-starting hosted service; it does not weaken fail-closed behavior because the second failure still raises.
    last_error: Optional[Exception] = None
    for attempt in range(2):
        try:
            resp = requests.post(endpoint, json=payload, headers=headers, timeout=15)
            if 200 <= resp.status_code < 300:
                data = resp.json()
                return int(data["id"])

            if 500 <= resp.status_code < 600:
                if attempt == 0:
                    time.sleep(3)
                    continue
                raise AuditError(f"Audit service HTTP {resp.status_code} server error: {resp.text}")

            # Any other non-2xx (401, 422, etc.): raise AuditError immediately with status code and response text, no retry.
            raise AuditError(f"Audit service HTTP {resp.status_code} error: {resp.text}")

        except requests.RequestException as e:
            last_error = e
            if attempt == 0:
                time.sleep(3)
                continue
            raise AuditError(f"Audit service connection/timeout error: {e}") from e

    raise AuditError(f"Audit service request failed after retry: {last_error}")
