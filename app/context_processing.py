"""
app/context_processing.py

Context processing pipeline for SentinelCI.

This module provides two entry points that map directly to architecture.md's
Workflow 1 (Context Retrieval):

  1. build_initial_context  — the always-run step.  Given a single SemgrepFinding
     and a GitOps handle, it extracts the ±50 lines surrounding the flagged code
     and packages everything into a ContextBundle.

  2. expand_context  — the conditional follow-up.  This only runs when the LLM's
     first assessment sets context_sufficient=False, signalling that the initial
     snippet wasn't enough to make a confident judgment.  It pulls in sibling /
     related files and appends truncated previews to the context bundle.

A helper, parse_semgrep_results, handles the mechanical step of turning Semgrep's
raw JSON output into typed SemgrepFinding objects before either entry point is
called.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models import ContextBundle, SemgrepFinding, Severity
from app.git_ops import GitOps


# ---------------------------------------------------------------------------
# Semgrep JSON → SemgrepFinding list
# ---------------------------------------------------------------------------

def parse_semgrep_results(results_path: str) -> list[SemgrepFinding]:
    """Parse the JSON file produced by ``semgrep ci --json`` into a list of
    :class:`SemgrepFinding` objects.

    Parameters
    ----------
    results_path:
        Absolute or relative path to the Semgrep JSON output file.

    Returns
    -------
    list[SemgrepFinding]
        One finding per entry in the ``"results"`` array.
    """
    raw_text = Path(results_path).read_text(encoding="utf-8")
    data = json.loads(raw_text)

    # Semgrep severity strings → our Severity enum.
    # NOTE: This mapping assumes Semgrep's default severity conventions
    # (ERROR → HIGH, WARNING → MEDIUM, INFO → LOW).  It will need
    # revisiting if custom rules with different severity conventions are
    # added later.
    severity_map: dict[str, Severity] = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }

    findings: list[SemgrepFinding] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        raw_severity = extra.get("severity", "")
        severity = severity_map.get(raw_severity, Severity.MEDIUM)

        findings.append(
            SemgrepFinding(
                rule_id=result["check_id"],
                file_path=result["path"],
                start_line=result["start"]["line"],
                end_line=result["end"]["line"],
                severity=severity,
                message=extra.get("message", ""),
                matched_code=extra.get("lines", ""),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Workflow 1a — cheap initial context (always runs)
# ---------------------------------------------------------------------------

def build_initial_context(
    finding: SemgrepFinding,
    git_ops: GitOps,
) -> ContextBundle:
    """Build the initial, inexpensive :class:`ContextBundle` for *finding*.

    This is the always-run first step of the context retrieval workflow.
    """
    surrounding_lines = git_ops.read_lines_around(
        finding.file_path,
        finding.start_line,
        finding.end_line,
        pad=50,
    )

    # Semgrep's matched_code field is unreliable for unauthenticated/free-tier
    # Semgrep OSS scans (some rules return "requires login" instead of the real
    # snippet), so the flagged code is read independently from the local checkout
    # via GitOps rather than trusted from Semgrep's JSON output. This makes the
    # pipeline correct regardless of the scanning account's login/tier status.
    actual_flagged_code = git_ops.read_lines_around(
        finding.file_path, finding.start_line, finding.end_line, pad=0
    )

    return ContextBundle(
        file_path=finding.file_path,
        flagged_code=actual_flagged_code,
        surrounding_lines=surrounding_lines,
        # TODO: Extracting the enclosing function reliably across languages
        # needs a real parser (e.g. tree-sitter).  Deliberately left unset
        # rather than faked with fragile regex heuristics.
        enclosing_function=None,
        nearby_comments=[],
        is_expanded=False,
    )


# ---------------------------------------------------------------------------
# Workflow 1b — expanded context (only when LLM says it needs more)
# ---------------------------------------------------------------------------

def expand_context(
    finding: SemgrepFinding,
    base_context: ContextBundle,
    git_ops: GitOps,
) -> ContextBundle:
    """Return a new :class:`ContextBundle` enriched with previews of related
    files.

    Only called when the LLM's first assessment indicates the initial context
    was not sufficient (``context_sufficient=False``).
    """
    related_paths = git_ops.find_related_files(finding.file_path)

    expanded_snippets: list[str] = []
    for path in related_paths:
        try:
            content = git_ops.read_file(path)
        except (UnicodeDecodeError, OSError):
            # Skip files that can't be read (binary blobs, permission
            # errors, broken symlinks, etc.).  One unreadable file should
            # never crash the entire scan.
            continue
        truncated = content[:2000]
        expanded_snippets.append(f"--- {path} ---\n{truncated}")

    combined_surrounding = (
        base_context.surrounding_lines
        + "\n\n"
        + "\n\n".join(expanded_snippets)
    )

    return ContextBundle(
        file_path=base_context.file_path,
        flagged_code=base_context.flagged_code,
        surrounding_lines=combined_surrounding,
        enclosing_function=base_context.enclosing_function,
        nearby_comments=base_context.nearby_comments,
        is_expanded=True,
        expanded_files=related_paths,
    )
