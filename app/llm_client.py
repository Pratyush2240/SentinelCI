"""
app/llm_client.py

Gemini API adapter for SentinelCI.

This module sends constructed security prompts to Google's Gemini API and converts
the response into a standardized LLMAssessment instance.
"""

from __future__ import annotations

import json
import os
from dotenv import load_dotenv
import google.generativeai as genai
from pydantic import ValidationError

from app.models import Confidence, ContextBundle, LLMAssessment, SemgrepFinding
from app.prompt_builder import build_prompt

# Load environment variables from .env file if present
load_dotenv()

def get_llm_assessment(
    finding: SemgrepFinding, context: ContextBundle
) -> LLMAssessment:
    """Send prompt to Gemini API and parse response into an LLMAssessment.

    Parameters
    ----------
    finding : SemgrepFinding
        The raw Semgrep finding being evaluated.
    context : ContextBundle
        The context bundle surrounding the flagged code.

    Returns
    -------
    LLMAssessment
        Standardized LLM evaluation result.
    """
    prompt = build_prompt(finding, context)

    # Note: Network/API exceptions from genai (e.g. rate limits, network connection loss)
    # are deliberately not caught here. Retry logic for network/API errors is a separate
    # concern and is explicitly out of scope for Step 5; let network errors propagate uncaught for now.
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")

    genai.configure(api_key=api_key)

    # Use current active Flash model identifier (configurable via GEMINI_MODEL env var)
    model_name = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
    model = genai.GenerativeModel(model_name)

    response = model.generate_content(prompt)
    raw_text = response.text or ""

    # Single try/except around parse-and-construct step (json.loads + building LLMAssessment).
    #
    # Decision #8 (Fail-safe, not fail-open):
    # When the LLM response is unparseable (json.JSONDecodeError) or schema-invalid (pydantic.ValidationError),
    # we fail toward Confidence.LOW rather than dropping the finding or assuming Confidence.HIGH.
    # Confidence.LOW ensures the action engine routes the finding to MANUAL_REVIEW, requiring a human
    # security engineer to inspect it instead of letting potential vulnerabilities pass through unverified
    # due to broken or malformed LLM outputs.
    try:
        clean_text = raw_text.strip()
        if clean_text.startswith("```"):
            lines = clean_text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            clean_text = "\n".join(lines).strip()

        data = json.loads(clean_text)

        # Early casing normalization: immediately uppercase the 'confidence' string value
        # inside the raw dict BEFORE constructing LLMAssessment to match the Confidence Enum.
        if isinstance(data, dict) and "confidence" in data and isinstance(data["confidence"], str):
            data["confidence"] = data["confidence"].upper()

        assessment = LLMAssessment(**data)
        print("[llm_client] Path taken: Normal Path (Successfully parsed LLMAssessment)")
        return assessment

    except (json.JSONDecodeError, ValidationError) as e:
        print(f"[llm_client] Path taken: Fallback Path (Failed to parse response: {type(e).__name__})")
        return LLMAssessment(
            confidence=Confidence.LOW,
            category="parse_error",
            reasoning=f"LLM response could not be parsed: {type(e).__name__}: {str(e)[:100]}",
            context_sufficient=True,
        )


if __name__ == "__main__":
    from app.models import Severity

    print("=== Manual Testing: get_llm_assessment ===")
    test_finding = SemgrepFinding(
        rule_id="python.lang.security.audit.hardcoded-password",
        file_path="test_secret.py",
        start_line=1,
        end_line=2,
        severity=Severity.HIGH,
        message="Hardcoded secret identified.",
        matched_code='aws_access_key_id = "AKIAFAKEEXAMPLE12345"',
    )

    test_context = ContextBundle(
        file_path="test_secret.py",
        flagged_code='aws_access_key_id = "AKIAFAKEEXAMPLE12345"',
        surrounding_lines='aws_access_key_id = "AKIAFAKEEXAMPLE12345"\naws_secret_access_key = "k3mR8pQzXvT2sLpN9wYc4hJf6eDaB1oGiUxZrWmA"',
        enclosing_function=None,
        nearby_comments=[],
        is_expanded=False,
    )

    result = get_llm_assessment(test_finding, test_context)
    print(f"\nResulting LLMAssessment:\n{result}")
