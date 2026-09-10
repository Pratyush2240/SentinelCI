"""
app/git_ops.py

Local Git repository operations module for SentinelCI.

This module reads directly from the LOCAL git checkout that GitHub Actions (or another
CI runner) has cloned onto the filesystem. It deliberately avoids making GitHub API
network requests for context retrieval, line extraction, file diffs, or git blame calls.

Why this matters for SentinelCI:
- Performance & Latency: Local disk access and git subprocess execution are fast syscalls,
  taking milliseconds compared to multi-hundred-millisecond network round-trips.
- Rate Limit Immunity: Reading from local disk eliminates GitHub REST/GraphQL API rate
  limiting completely, keeping the dynamic "expanded context" retrieval path fast and resilient.
"""

from __future__ import annotations

import pathlib
import subprocess


class GitOps:
    """
    Provides local file system and Git repository operations for SentinelCI context extraction.
    """

    def __init__(self, repo_root: str = ".") -> None:
        self.repo_root = pathlib.Path(repo_root)

    def read_file(self, file_path: str) -> str:
        """
        Reads and returns the full text content of a file relative to repo_root,
        using UTF-8 encoding with errors='replace' to prevent encoding failures on binary/unusual files.
        """
        target_path = self.repo_root / file_path
        return target_path.read_text(encoding="utf-8", errors="replace")

    def read_lines_around(self, file_path: str, start_line: int, end_line: int, pad: int = 50) -> str:
        """
        Reads the file, splits into lines, and returns lines from (start_line - 1 - pad)
        to (end_line + pad), clamped to valid bounds [0, len(lines)].

        Note: start_line and end_line are 1-indexed as reported by Semgrep, while Python lists are 0-indexed.
        """
        content = self.read_file(file_path)
        lines = content.splitlines()

        # Handle 1-indexed lines to 0-indexed slice ranges
        start_idx = max(0, start_line - 1 - pad)
        end_idx = min(len(lines), end_line + pad)

        return "\n".join(lines[start_idx:end_idx])

    def blame(self, file_path: str, line: int) -> str:
        """
        Runs `git blame -L {line},{line} -- {file_path}` as a subprocess in repo_root.
        Returns stripped stdout (or empty string if blame fails).
        """
        result = subprocess.run(
            ["git", "blame", "-L", f"{line},{line}", "--", file_path],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip()

    def diff_against_base(self, base_sha: str, file_path: str) -> str:
        """
        Runs `git diff {base_sha} -- {file_path}` as a subprocess in repo_root.
        Returns unstripped stdout to preserve raw diff formatting.
        """
        result = subprocess.run(
            ["git", "diff", base_sha, "--", file_path],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout

    def get_changed_files(self, base_sha: str) -> list[str]:
        """
        Runs `git diff --name-only {base_sha}` as a subprocess in repo_root.
        Returns a list of file paths that changed relative to base_sha.
        Excludes deleted files if Git reports them (a deleted file can't be 
        scanned by Semgrep) — filter these out by checking os.path.exists() 
        on each returned path relative to repo_root before including it.
        Returns an empty list if the command fails or produces no output — 
        do not raise an exception here; let the caller (main.py) decide how 
        to handle zero changed files.
        """
        result = subprocess.run(
            ["git", "diff", "--name-only", base_sha],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        changed_files: list[str] = []
        for line in result.stdout.splitlines():
            path_str = line.strip()
            if not path_str:
                continue
            target_path = self.repo_root / path_str
            if target_path.exists() and target_path.is_file():
                changed_files.append(path_str)

        return changed_files

    def find_related_files(self, file_path: str) -> list[str]:
        """
        PLACEHOLDER HEURISTIC:
        Returns up to 5 sibling files in the same directory as file_path (excluding file_path itself),
        formatted as relative paths string to repo_root.

        NOTE: Same-directory sibling discovery is a crude, temporary proxy for "related files".
        A production implementation would perform AST import-graph analysis, dependency resolution,
        or git commit co-edit history analysis to find genuinely related files.
        This placeholder should NOT be presented as a finished design decision.
        """
        target_path = self.repo_root / file_path
        parent_dir = target_path.parent

        if not parent_dir.exists() or not parent_dir.is_dir():
            return []

        related: list[str] = []
        for entry in parent_dir.iterdir():
            if entry.is_file() and entry != target_path:
                try:
                    rel_path = str(entry.relative_to(self.repo_root))
                except ValueError:
                    rel_path = str(entry)
                related.append(rel_path)
                if len(related) >= 5:
                    break

        return related
