"""
app/models.py

Shared data contracts for SentinelCI — a CI/CD security scanner combining Semgrep
(deterministic static analysis) with an LLM reasoning layer to reduce false positives.

These Pydantic v2 models define the core interfaces that every module in SentinelCI
depends on. Keeping LLM-specific logic and provider schemas out of this file allows
swapping or updating LLM providers (e.g., OpenAI, Anthropic, Gemini, local models)
without altering downstream code or data pipeline logic.
"""

from __future__ import annotations


from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """
    Severity comes directly from Semgrep's rule metadata and is deterministic.
    It is NEVER set or modified by the LLM.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    """
    Confidence comes from the LLM's contextual judgment.
    This is an INDEPENDENT axis from Severity — do NOT conflate these into a single score.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Action(str, Enum):
    """
    Action determined for the CI/CD pipeline based on finding assessment.
    """
    BLOCK_BUILD = "BLOCK_BUILD"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    BUILD_PASS = "BUILD_PASS"


class SemgrepFinding(BaseModel):
    """
    One raw finding parsed from Semgrep's --json output.
    """
    rule_id: str
    file_path: str
    start_line: int
    end_line: int
    severity: Severity
    message: str
    matched_code: str


class ContextBundle(BaseModel):
    """
    Output of the context-processing step, provider-agnostic.
    """
    file_path: str
    flagged_code: str
    surrounding_lines: str  # The ±50 lines around the flagged code
    enclosing_function: Optional[str] = None
    nearby_comments: list[str] = Field(default_factory=list)
    is_expanded: bool = False  # True if this went through a second, expanded-context retrieval pass
    expanded_files: list[str] = Field(default_factory=list)  # Only populated if is_expanded is True


class LLMAssessment(BaseModel):
    """
    The structured response any LLM provider adapter must produce,
    so the rest of the app never needs to know which provider is being used.
    """
    confidence: Confidence
    category: str  # e.g., "hardcoded_credential", "sql_injection"
    reasoning: str
    context_sufficient: bool  # False triggers a second LLM call with expanded context


class Finding(BaseModel):
    """
    The fully assembled record written to an audit log.
    """
    finding_id: Optional[int] = None  # Assigned externally on first write
    semgrep: SemgrepFinding
    context: ContextBundle
    assessment: LLMAssessment
    action: Action
    repo: str
    pr_number: int
    head_sha: str
