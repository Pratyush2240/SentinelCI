"""
app/main.py

End-to-end orchestration entry point for SentinelCI.

This module wires together all SentinelCI pipeline components:
1. Parse GitHub Actions PR event context
2. Run Semgrep static analysis
3. Parse findings into SemgrepFinding models
4. Extract local context bundles (GitOps & ContextProcessing)
5. Evaluate findings via LLM reasoning adapter (LLMClient & PromptBuilder)
6. Perform two-pass context expansion if LLMAssessment.context_sufficient is False
7. Evaluate policy decisions via DecisionEngine lookup matrix
8. Output human-readable summary to stdout and structured JSON to ./output/sentinelci_results.json
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from dotenv import load_dotenv

from app.context_processing import build_initial_context, expand_context, parse_semgrep_results
from app.decision_engine import get_decision
from app.git_ops import GitOps
from app.llm_client import get_llm_assessment

# Load local environment variables from .env file if present
load_dotenv()


def run_semgrep_scan(
    changed_files: list[str],
    output_path: str = "output/semgrep_results.json",
) -> str:
    """Execute Semgrep CLI scanner on specified changed files and save JSON output to output_path.

    Parameters
    ----------
    changed_files : list[str]
        List of changed file paths to scan.
    output_path : str
        Path where the Semgrep JSON output will be saved.

    Returns
    -------
    str
        Path to the generated Semgrep JSON results file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if not changed_files:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"results": []}, f, indent=2)
        return output_path

    # Shell out to Semgrep CLI with JSON output formatting for specific changed files
    cmd = [
        "semgrep",
        "scan",
        "--config",
        "p/secrets",
        "--json",
        "--output",
        output_path,
    ] + changed_files

    subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    return output_path


def main() -> None:
    """Execute the SentinelCI pipeline end-to-end for a Pull Request run."""
    # Unconditional reading of GitHub Actions environment variables
    github_event_path = os.environ["GITHUB_EVENT_PATH"]
    github_sha = os.environ["GITHUB_SHA"]
    github_base_ref = os.environ["GITHUB_BASE_REF"]

    # Load GitHub PR event JSON payload
    with open(github_event_path, "r", encoding="utf-8") as f:
        event_data = json.load(f)

    repo_name = event_data.get("repository", {}).get("full_name", "unknown/repo")
    pr_number = event_data.get("number") or event_data.get("pull_request", {}).get("number", 0)

    print(f"=== SentinelCI Security Scan ===")
    print(f"Repository: {repo_name} | PR #{pr_number} | Commit: {github_sha[:7]} | Base: {github_base_ref}")

    git_ops = GitOps(repo_root=".")

    # NOTE: Using github_base_ref (base branch name like "main") rather than a precise base SHA
    # is a known simplification for now, and may need revisiting once the real GitHub Actions
    # checkout behavior (fetch depth, detached HEAD state) is tested in Step 8's actual CI environment.
    changed_files = git_ops.get_changed_files(github_base_ref)

    # 1. Run Semgrep on changed files and parse raw findings
    semgrep_json_path = run_semgrep_scan(changed_files, "output/semgrep_results.json")
    findings = parse_semgrep_results(semgrep_json_path)

    results: list[dict] = []

    print(f"Semgrep Scan Complete: {len(findings)} finding(s) detected.\n")

    # 2. Process each finding through the SentinelCI pipeline
    for index, finding in enumerate(findings, start=1):
        # NOTE (FAILURE ISOLATION): Wrap per-finding processing in a try/except block
        # so an unhandled exception in processing one finding does not crash the run for others.
        try:
            # Step 2a: Extract initial context bundle (±50 lines)
            context = build_initial_context(finding, git_ops)

            # Step 2b: Send prompt to LLM and get structured assessment
            assessment = get_llm_assessment(finding, context)

            # NOTE (RETRY CAP): If the LLM indicates context is insufficient, perform exactly
            # one expanded-context retrieval pass and re-assess — capped at 1 retry (no infinite loops).
            if not assessment.context_sufficient:
                context = expand_context(finding, context, git_ops)
                assessment = get_llm_assessment(finding, context)

            # Step 2c: Evaluate policy decision from Severity x Confidence matrix
            action, override_eligible = get_decision(finding, assessment)

            result_record = {
                "finding_id": index,
                "file_path": finding.file_path,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "severity": finding.severity.value,
                "confidence": assessment.confidence.value,
                "action": action.value,
                "override_eligible": override_eligible,
                "category": assessment.category,
                "reasoning": assessment.reasoning,
                "error": None,
            }

        except Exception as e:
            # Per-finding fallback error record
            result_record = {
                "finding_id": index,
                "file_path": getattr(finding, "file_path", "unknown"),
                "start_line": getattr(finding, "start_line", 0),
                "end_line": getattr(finding, "end_line", 0),
                "severity": finding.severity.value if hasattr(finding, "severity") and hasattr(finding.severity, "value") else "UNKNOWN",
                "confidence": None,
                "action": "ERROR",
                "override_eligible": False,
                "category": "processing_error",
                "reasoning": f"Processing failed: {type(e).__name__}: {e}",
                "error": f"{type(e).__name__}: {e}",
            }

        results.append(result_record)

    # 3. Print human-readable summary to stdout
    if results:
        print(f"{'ID':<4} | {'File Path & Line':<30} | {'Severity':<9} | {'Confidence':<10} | {'Action':<14} | {'Status':<8}")
        print("-" * 85)
        for res in results:
            loc = f"{res['file_path']}:{res['start_line']}"
            conf = res['confidence'] or "N/A"
            status = "ERROR" if res['action'] == "ERROR" else "OK"
            print(f"{res['finding_id']:<4} | {loc:<30} | {res['severity']:<9} | {conf:<10} | {res['action']:<14} | {status:<8}")

    # 4. Write structured results to ./output/sentinelci_results.json
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    results_file = output_dir / "sentinelci_results.json"

    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nStructured results successfully written to {results_file}")


if __name__ == "__main__":
    main()
