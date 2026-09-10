"""
app/prompt_builder.py

Prompt assembly module for SentinelCI.

This module constructs the exact prompt string sent to the LLM (Gemini API)
by combining a Semgrep finding metadata with its retrieved ContextBundle.

It sits between app/context_processing.py (which builds ContextBundle) and
app/llm_client.py (which executes the LLM request and parses the output).
"""

from __future__ import annotations

from app.models import ContextBundle, SemgrepFinding

# Note: Confidence values in this schema instruction are intentionally lowercase
# ("high", "medium", "low"). Uppercase normalization to match the Confidence enum in
# models.py is handled in llm_client.py, NOT here.
RESPONSE_SCHEMA_INSTRUCTIONS = """RESPONSE FORMAT INSTRUCTIONS:
Respond ONLY with a single valid JSON object matching the exact schema below.
Do NOT include markdown code blocks (e.g. ```json), preambles, or postscript text.

"confidence" measures how confident you are that this is a GENUINE, REAL, exploitable 
secret/vulnerability — NOT how confident you are in your own reasoning or judgment. 
If you believe this is a false positive (test fixture, dummy data, mock, safe example), 
that belief should be reflected as LOW confidence, because you do not believe a real 
vulnerability exists here.

{
  "confidence": "high" | "medium" | "low",
  "category": "<short string label, e.g. hardcoded_secret, sql_injection>",
  "reasoning": "<2-4 sentences explaining your confidence judgment based strictly on context>",
  "context_sufficient": true | false
}"""


def build_prompt(finding: SemgrepFinding, context: ContextBundle) -> str:
    """Assembles a structured prompt for the LLM from a Semgrep finding and its
    associated context bundle.

    This function is strictly pure: no I/O, no network calls, and no external dependencies.

    Parameters
    ----------
    finding : SemgrepFinding
        The raw finding parsed from Semgrep JSON output.
    context : ContextBundle
        The context bundle retrieved from the local repository.

    Returns
    -------
    str
        The complete prompt string ready for transmission to the LLM.
    """
    # Note: Use context.flagged_code verbatim (read directly from source via GitOps).
    # NEVER fall back to finding.matched_code as Semgrep OSS can return "requires login"
    # for free-tier rules, which would corrupt prompt context.
    flagged_code = context.flagged_code

    enclosing_func_str = (
        context.enclosing_function
        if context.enclosing_function is not None
        else "None detected"
    )

    nearby_comments_str = (
        "\n".join(context.nearby_comments)
        if context.nearby_comments
        else "None"
    )

    expanded_files_str = (
        ", ".join(context.expanded_files)
        if context.is_expanded and context.expanded_files
        else ("None" if not context.is_expanded else "None included")
    )

    prompt = f"""You are an expert security code reviewer evaluating static analysis findings in a CI/CD pipeline.
Your job is to determine whether a flagged code pattern is a genuine, exploitable security vulnerability or a false positive (such as a test fixture, dummy credential, mock, documentation example, or safe usage).

=== FINDING METADATA ===
Rule ID: {finding.rule_id}
Severity: {finding.severity.value}
File Path: {finding.file_path}
Line Range: {finding.start_line}-{finding.end_line}
Message: {finding.message}

CRITICAL INSTRUCTION ON SEVERITY:
Severity indicates potential impact IF the finding is real. It must NOT influence your confidence judgment.
Base your confidence assessment strictly on the code and context provided below, regardless of whether severity is CRITICAL, HIGH, MEDIUM, or LOW.

=== FLAGGED CODE ===
{flagged_code}

=== SURROUNDING CONTEXT ===
Enclosing Function: {enclosing_func_str}
Nearby Comments:
{nearby_comments_str}
Is Expanded Context Pass: {context.is_expanded}
Expanded Related Files: {expanded_files_str}

Surrounding Code & Context Snippets:
{context.surrounding_lines}

=== CONTEXT SUFFICIENCY EVALUATION ===
Evaluate if the provided context is sufficient for you to make a confident judgment.
- Set "context_sufficient" to false if you genuinely cannot judge confidence without seeing additional repository context (for example, whether a credential or config is used in production vs test setup).
- Set "context_sufficient" to true if the given context is enough to evaluate the finding.
This is your self-assessment of whether additional file context is needed before finalizing review.

=== OUTPUT FORMAT ===
{RESPONSE_SCHEMA_INSTRUCTIONS}"""

    return prompt


if __name__ == "__main__":
    from app.models import Severity

    # Manual verification sample run
    dummy_finding = SemgrepFinding(
        rule_id="python.lang.security.audit.hardcoded-password",
        file_path="app/config.py",
        start_line=12,
        end_line=12,
        severity=Severity.HIGH,
        message="Hardcoded password string identified.",
        matched_code="requires login",  # Deliberately fake Semgrep output
    )

    dummy_context = ContextBundle(
        file_path="app/config.py",
        flagged_code='SECRET_KEY = "dummy-secret-key-for-testing"',
        surrounding_lines='''10: # Configuration file
11: 
12: SECRET_KEY = "dummy-secret-key-for-testing"
13: 
14: DEBUG = True''',
        enclosing_function=None,
        nearby_comments=["# Configuration file"],
        is_expanded=False,
    )

    generated_prompt = build_prompt(dummy_finding, dummy_context)
    print("=== GENERATED PROMPT PREVIEW ===")
    print(generated_prompt)
