# SentinelCI — Build Workflow Log

Tracks: what's been built, in what order, which steps were done via an Antigravity prompt vs. manually, and what's next. Update after every step.

Working mode agreed with Claude: Claude gives one detailed, ready-to-run prompt per file/step. Pratyush runs it in Antigravity, reviews the output, confirms it's done, then moves to the next step. Claude flags anywhere a manual action (not a prompt) is faster/more appropriate — e.g. creating a GitHub secret, signing up for an API key — rather than burning a prompt on something that isn't really a coding task.

---

## Build order (bottom-up, each step depends only on prior ones)

| # | File | Purpose | Status |
|---|---|---|---|
| 1 | `app/models.py` | Shared data contracts (SemgrepFinding, ContextBundle, LLMAssessment, Finding, enums) | **DONE** |
| 2 | `app/git_ops.py` | Read local checkout: file contents, ±N lines, blame, related files | **DONE (manually verified)** |
| 3 | `app/context_processing.py` | Parse Semgrep JSON, build initial + expanded ContextBundle | **DONE (manually verified against real Semgrep output)** |
| 4 | `app/prompt_builder.py` | Assemble SemgrepFinding + ContextBundle into the LLM prompt string | **DONE (manually verified)** |
| 5 | `app/llm_client.py` | Gemini Flash adapter → returns LLMAssessment | **DONE (manually verified)** |
| 6 | `app/decision_engine.py` | Severity × Confidence matrix, override eligibility | **DONE (manually verified)** |
| 7 | `app/main.py` | Wire 1–6 together end-to-end for one PR run | **DONE (manually verified)** |
| 8 | `.github/workflows/security-scan.yml` | CI trigger for the whole pipeline | Not started |
| 9 | Audit Service (FastAPI + Postgres) | Persist findings, separate from the CI workflow | Not started |
| 10 | Override workflow (`issue_comment` trigger) | Slash-command override, two independent checks | Not started |
| 11 | Test-set construction + evaluation | Real evidence for resume claims — see decisions.md #5 caveat | Not started |

**Manual (non-prompt) actions needed at some point, not yet done:**
- Create a GitHub repo for this project (if not already done) — trivial, don't burn a prompt on it.
- Sign up for Google AI Studio, generate a Gemini API key, add it as `GEMINI_API_KEY` in GitHub Secrets.
- Decide on and sign up for the audit DB host (Supabase or Neon) — comparing the two free tiers is a 10-minute manual task, not something to prompt-generate.
- Add `SENTINELCI_AUDIT_API_KEY` and `SENTINELCI_AUDIT_URL` to GitHub Secrets once the audit service exists (step 9).

---

## Step 1 — `app/models.py` ✅ DONE

**What it does:** Defines `Severity`, `Confidence`, `Action` enums and `SemgrepFinding`, `ContextBundle`, `LLMAssessment`, `Finding` Pydantic models — the shared contract every other module imports.

**Why this is step 1:** Every other module (`git_ops`, `context_processing`, `prompt_builder`, `llm_client`, `decision_engine`) either consumes or produces one of these types. Building it first means every later step has a concrete target shape to fill in, rather than inventing ad-hoc dicts that would need to be reconciled later.

**Issues caught in review:**
1. **Enum casing mismatch (real bug, fix deferred to Step 5):** enums use uppercase values (`"HIGH"`), but the LLM prompt schema requests lowercase. Fix lives in `llm_client.py` via `.upper()` normalization on parse — not in `models.py` itself.
2. **Docstring ordering (cosmetic):** `from __future__ import annotations` was placed before the module docstring in the first draft, so it wasn't actually assigned to `__doc__`. Low priority fix.

**File ownership note:** Antigravity also generates its own `Decision.md` / `workflow.md` with implementation-level notes. Reconciliation of the two sets of docs is explicitly deferred to the end of the build (Pratyush's call) — flagged as a real cost to pay later, not resolved yet.

---

## Step 2 — `app/git_ops.py` ✅ DONE (manually verified)

**What it does:** `read_file`, `read_lines_around`, `blame`, `diff_against_base`, `find_related_files` — all operate on the local git checkout, no GitHub API calls.

**Manual verification performed (not just code review):**
- `read_file`: confirmed real file content returned.
- `read_lines_around`: confirmed by manually counting lines in the actual file — pad/clamp math (`lo = start-1-pad`, `hi = end+pad`) is correct, no off-by-one.
- `blame`: confirmed real commit hash/author/timestamp returned once repo had at least one commit.
- `diff_against_base`: initially looked broken (empty output on two test SHAs), but root-caused correctly — the file being diffed (`models.py`) genuinely hadn't changed between those two commits (the only change was removing an accidentally-committed `__pycache__` folder). Empty diff was the correct result, not a bug. Not yet tested against a commit that actually modifies `models.py` — worth doing once there's a reason to.
- `find_related_files`: confirmed real sibling files listed.

**Process note:** `__pycache__/` was accidentally committed to the repo. Fixed via `.gitignore` + `git rm -r --cached`. Should be gitignored from commit #1 on any future Python project.

---

## Step 3 — `app/context_processing.py` ✅ DONE (manually verified against real Semgrep output)

**What it does:** `parse_semgrep_results` turns raw `semgrep --json` output into `SemgrepFinding` objects. `build_initial_context` and `expand_context` build the always-run and conditional-expansion `ContextBundle`s.

**Manual verification performed:**
- Installed Semgrep, ran real scans against a test file with a planted fake AWS key.
- First attempt (`AKIAIOSFODNN7EXAMPLE`, AWS's official docs example key) produced 0 findings — root-caused to secret-scanners commonly denylisting well-known example/placeholder credentials specifically to avoid flagging documentation. Switched to a non-well-known fake key in the same format; got 2 real findings.
- Ran `parse_semgrep_results` against the real `semgrep-results.json`: no crash, correct field mapping (file path, line numbers, severity all correct) — confirms the JSON-shape assumptions in the parser hold against actual Semgrep output, not just a guessed schema.

**Real bug caught via this testing (not found by code review):** Semgrep OSS's community/registry rules return the literal string `"requires login"` in the lines field (`→ matched_code`) for many rules, gating the actual matched snippet behind a paid/logged-in tier. This would have silently fed `"requires login"` into the LLM prompt as the "flagged code" — degrading the core value proposition (contextual reasoning about the ACTUAL flagged code, per architecture.md §2) to reasoning about a placeholder string, for any rule that gates snippets this way.

**Fix:** `build_initial_context` no longer trusts `finding.matched_code` from Semgrep's JSON at all. Instead it calls `git_ops.read_lines_around(finding.file_path, finding.start_line, finding.end_line, pad=0)` to read the actual flagged line(s) directly from the local checkout — independent of Semgrep's account tier or licensing. Verified: `ctx.flagged_code` now shows the real code, not the placeholder.

**Why this is a good decisions.md entry, not just a bugfix note:** this is exactly the kind of thing that only surfaces when you test against a real tool's real output rather than an assumed schema — logged as decision #10.

---

## Step 4 — `app/prompt_builder.py` ✅ DONE (manually verified)

**What it does:** `build_prompt` assembles a `SemgrepFinding` and a `ContextBundle` into the exact prompt string sent to Gemini API, including task framing, severity-independence instruction, flagged code from source, surrounding lines, context-sufficiency evaluation rules, and `RESPONSE_SCHEMA_INSTRUCTIONS`.

**Manual verification performed:**
- Executed `python -m app.prompt_builder` with sample test data (`SemgrepFinding` + `ContextBundle`).
- Verified prompt output format: task framing correctly ordered, severity independence explicitly instructed, flagged code read from local source snippet, `RESPONSE_SCHEMA_INSTRUCTIONS` properly appended.

---

## Step 5 — `app/llm_client.py` ✅ DONE (manually verified)

**What it does:** `get_llm_assessment` passes `finding` and `context` to `build_prompt()`, queries Gemini API (`gemini-3.6-flash`), normalizes lowercase confidence values to uppercase in raw JSON dict before constructing `LLMAssessment`, and enforces Decision #8 fail-safe error handling (`Confidence.LOW`, `category="parse_error"`) on malformed responses.

**Manual verification performed:**
- Tested against live Gemini API using real credentials from `.env`.
- Executed `python -m app.llm_client`: API call succeeded on normal path, raw lowercase `"medium"` confidence correctly uppercased to `<Confidence.MEDIUM: 'MEDIUM'>`.
- Executed parse failure fallback tests: `json.JSONDecodeError` and `ValidationError` properly caught and fallback `LLMAssessment` returned with `Confidence.LOW`.

---

## Step 6 — `app/decision_engine.py` ✅ DONE (manually verified)

**What it does:** `DECISION_MATRIX` maps the 12 `(Severity, Confidence)` combinations to `(Action, is_override_eligible)` tuples. `get_decision()` retrieves decisions and raises `KeyError` on missing pairs per Decision #8 fail-safe philosophy. `is_override_eligible()` provides a helper for re-evaluating override eligibility at slash-command override time.

**Manual verification performed:**
- Executed `python -m app.decision_engine` iterating across all 12 `(Severity, Confidence)` combinations.
- Confirmed visually that only `(Critical, Low)` and `(High, Low)` evaluate to `is_override_eligible = True`.
- Verified that `is_override_eligible()` helper output matches `get_decision()` across all 12 matrix cells.

---

## Step 7 — `app/main.py` ✅ DONE (manually verified)

**What it does:** Orchestrates the end-to-end SentinelCI pipeline run. Reads GitHub Actions environment variables (`GITHUB_EVENT_PATH`, `GITHUB_SHA`, `GITHUB_BASE_REF`), executes Semgrep CLI, extracts context, queries LLM reasoning adapter with single-retry context expansion cap when `context_sufficient=False`, evaluates policy decisions via `decision_engine`, enforces per-finding failure isolation (`try/except`), prints human-readable stdout summary, and outputs structured results to `./output/sentinelci_results.json`.

**Manual verification performed:**
- Created `test_fixtures/fake_pr_event.json` and updated `.gitignore` with `output/`.
- Executed `python -m app.main` with `GITHUB_EVENT_PATH="test_fixtures/fake_pr_event.json"`, `GITHUB_SHA="0ce651a"`, and `GITHUB_BASE_REF="main"`.
- Verified stdout table summary printed correctly and `output/sentinelci_results.json` was created containing full structured result.

---

*(Next entry: Step 8, .github/workflows/security-scan.yml)*


