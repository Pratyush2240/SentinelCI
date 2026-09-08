"""
app/decision_engine.py

Decision engine for SentinelCI.

This module evaluates static analysis Severity (from Semgrep) against contextual
Confidence (from LLMAssessment) using an explicit 12-cell lookup matrix to determine
the final CI action (BLOCK_BUILD, MANUAL_REVIEW, BUILD_PASS) and human override eligibility.
"""

from __future__ import annotations

from app.models import Action, Confidence, LLMAssessment, SemgrepFinding, Severity

# ---------------------------------------------------------------------------
# 12-cell Policy Matrix: (Severity, Confidence) -> (Action, is_override_eligible)
#
# NOTE: Per Decision #3 (and decisions.md #3/#4), override eligibility requires the specific
# conjunction of high/critical severity AND low confidence — indicating genuine model
# uncertainty under high-impact conditions where human review adds missing signal.
# Override eligibility is NOT enabled for any other Block Build cell (Critical/High,
# Critical/Medium, High/High, High/Medium), because overriding those would bypass a
# well-supported security gate on human say-so alone.
# ---------------------------------------------------------------------------
DECISION_MATRIX: dict[tuple[Severity, Confidence], tuple[Action, bool]] = {
    # Critical Severity
    (Severity.CRITICAL, Confidence.HIGH): (Action.BLOCK_BUILD, False),
    (Severity.CRITICAL, Confidence.MEDIUM): (Action.BLOCK_BUILD, False),
    (Severity.CRITICAL, Confidence.LOW): (Action.BLOCK_BUILD, True),

    # High Severity
    (Severity.HIGH, Confidence.HIGH): (Action.BLOCK_BUILD, False),
    (Severity.HIGH, Confidence.MEDIUM): (Action.BLOCK_BUILD, False),
    (Severity.HIGH, Confidence.LOW): (Action.BLOCK_BUILD, True),

    # Medium Severity
    (Severity.MEDIUM, Confidence.HIGH): (Action.BUILD_PASS, False),
    (Severity.MEDIUM, Confidence.MEDIUM): (Action.MANUAL_REVIEW, False),
    (Severity.MEDIUM, Confidence.LOW): (Action.MANUAL_REVIEW, False),

    # Low Severity
    (Severity.LOW, Confidence.HIGH): (Action.BUILD_PASS, False),
    (Severity.LOW, Confidence.MEDIUM): (Action.BUILD_PASS, False),
    (Severity.LOW, Confidence.LOW): (Action.MANUAL_REVIEW, False),
}


def get_decision(finding: SemgrepFinding, assessment: LLMAssessment) -> tuple[Action, bool]:
    """Look up the (Action, is_override_eligible) decision for a given finding and assessment.

    Parameters
    ----------
    finding : SemgrepFinding
        The Semgrep finding containing the severity rating.
    assessment : LLMAssessment
        The LLM evaluation output containing confidence rating.

    Returns
    -------
    tuple[Action, bool]
        A tuple of (Action, is_override_eligible).

    Raises
    ------
    KeyError
        If the (Severity, Confidence) pair is not found in the decision matrix.
        Per Decision #8 fail-safe philosophy, missing key errors raise an exception
        rather than silently defaulting to a lenient action like BUILD_PASS.
    """
    key = (finding.severity, assessment.confidence)
    if key not in DECISION_MATRIX:
        raise KeyError(
            f"Unrecognized (Severity, Confidence) key pair: {key}. "
            "Policy engine cannot determine action safely."
        )
    return DECISION_MATRIX[key]


def is_override_eligible(severity: Severity, confidence: Confidence) -> bool:
    """Check if a given (Severity, Confidence) combination is eligible for human override.

    Convenience wrapper used by the slash-command override workflow (Step 10)
    to re-verify override eligibility against a stored finding's severity/confidence.

    Parameters
    ----------
    severity : Severity
        The rule severity rating.
    confidence : Confidence
        The LLM confidence assessment rating.

    Returns
    -------
    bool
        True if the combination is eligible for override, False otherwise.
    """
    key = (severity, confidence)
    if key not in DECISION_MATRIX:
        raise KeyError(
            f"Unrecognized (Severity, Confidence) key pair: {key}."
        )
    _, override_eligible = DECISION_MATRIX[key]
    return override_eligible


if __name__ == "__main__":
    print("=== SentinelCI Decision Matrix Visual Verification ===")
    print(f"{'Severity':<12} | {'Confidence':<10} | {'Action':<15} | {'Override Eligible':<18}")
    print("-" * 65)

    dummy_finding = SemgrepFinding(
        rule_id="test-rule",
        file_path="app/test.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        message="Test message",
        matched_code="test()",
    )

    dummy_assessment = LLMAssessment(
        confidence=Confidence.HIGH,
        category="test",
        reasoning="Test reasoning",
        context_sufficient=True,
    )

    for severity in Severity:
        for confidence in Confidence:
            # Construct test objects for each matrix cell
            test_finding = dummy_finding.model_copy(update={"severity": severity})
            test_assessment = dummy_assessment.model_copy(update={"confidence": confidence})

            action, override_eligible = get_decision(test_finding, test_assessment)

            # Re-verify via is_override_eligible helper function
            helper_check = is_override_eligible(severity, confidence)
            assert override_eligible == helper_check, "Helper function mismatch!"

            print(
                f"{severity.value:<12} | {confidence.value:<10} | "
                f"{action.value:<15} | {str(override_eligible):<18}"
            )
