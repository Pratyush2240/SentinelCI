"""
app/github_notifier.py

Implements architecture.md §6's sticky-comment behavior for two of the three
notification tiers (BLOCK_BUILD and MANUAL_REVIEW).
"""

from __future__ import annotations

import requests


def post_or_update_comment(findings: list, pr_number: int, repo: str, token: str) -> None:
    """Post or update a sticky GitHub PR comment summarizing security findings.

    Parameters
    ----------
    findings : list
        List of result dictionaries or finding objects from the security scan.
    pr_number : int
        The Pull Request number.
    repo : str
        The repository full name (e.g. 'owner/repo').
    token : str
        GitHub API access token.
    """
    # Filter findings to only those whose action is BLOCK_BUILD or MANUAL_REVIEW
    filtered_findings = []
    for item in findings:
        action = item.get("action") if isinstance(item, dict) else getattr(item, "action", None)
        if hasattr(action, "value"):
            action = action.value
        if action in ("BLOCK_BUILD", "MANUAL_REVIEW"):
            filtered_findings.append(item)

    # If the filtered list is empty, do nothing and return (no comment posted) — per architecture.md §6, Build Pass stays silent on the PR conversation.
    # Note: This deliberately does NOT delete a stale comment from a prior push if all findings are now resolved — known limitation, deferred post-MVP.
    if not filtered_findings:
        return

    marker = "<!-- sentinelci-sticky-comment -->"

    lines = [
        marker,
        "## SentinelCI Security Scan Findings",
        "",
        "| Finding ID | File Path & Line | Severity | Confidence | Action |",
        "| --- | --- | --- | --- | --- |",
    ]

    for finding in filtered_findings:
        if isinstance(finding, dict):
            fid = finding.get("finding_id", "")
            file_path = finding.get("file_path", "")
            start_line = finding.get("start_line", "")
            sev = finding.get("severity", "")
            conf = finding.get("confidence", "")
            act = finding.get("action", "")
        else:
            fid = getattr(finding, "finding_id", "")
            file_path = getattr(finding, "file_path", "")
            start_line = getattr(finding, "start_line", "")
            sev = getattr(finding, "severity", "")
            conf = getattr(finding, "confidence", "")
            act = getattr(finding, "action", "")

        sev = getattr(sev, "value", sev)
        conf = getattr(conf, "value", conf) or "N/A"
        act = getattr(act, "value", act)

        loc = f"{file_path}:{start_line}" if start_line else str(file_path)
        lines.append(f"| {fid} | {loc} | {sev} | {conf} | {act} |")

    body = "\n".join(lines)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

    # GET existing comments to locate previous sticky comment
    get_resp = requests.get(comments_url, headers=headers)
    get_resp.raise_for_status()

    comments = get_resp.json()
    existing_comment_id = None

    if isinstance(comments, list):
        for comment in comments:
            if isinstance(comment, dict) and marker in comment.get("body", ""):
                existing_comment_id = comment.get("id")
                break

    if existing_comment_id:
        # Edit existing comment in place (sticky comment behavior)
        patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_comment_id}"
        patch_resp = requests.patch(patch_url, headers=headers, json={"body": body})
        patch_resp.raise_for_status()
    else:
        # Create a new comment
        post_resp = requests.post(comments_url, headers=headers, json={"body": body})
        post_resp.raise_for_status()
