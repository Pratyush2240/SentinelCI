# SentinelCI — Decision Log

Personal reference doc. Every non-trivial choice made on this project, why it was made, what else was considered, and what would make me reconsider it. Not meant for a recruiter to read — meant so I can defend any part of this cold, without re-deriving it from scratch under pressure.

Format per entry: **Decision → Alternatives considered → Why this one → What would change my mind.**

---

### 1. Two independent GitHub Actions workflows, no standalone server

**Decision:** Security Scan (PR trigger) and Override (issue_comment trigger) are two separate GitHub Actions workflows. No always-on backend server for the core scanning logic — GitHub-hosted runners provide compute per-run.

**Alternatives considered:**
- A GitHub App with its own hosted webhook listener (persistent server, receives all GitHub events, decides what to do).
- A single workflow handling both triggers with conditional branching.

**Why this one:** No infrastructure to run/pay for/secure beyond the audit service. GitHub Actions already IS the compute + trigger system. A GitHub App would need its own hosting, its own auth (webhook secret verification), and buys nothing extra for this scope. Two separate workflows (vs. one branching workflow) map cleanly to two genuinely different trigger types and permission needs — cleaner to reason about and secure independently (Security Scan needs `pull_request` read access; Override needs `issue_comment` + ability to check commenter permissions).

**What would change my mind:** If the system needed to react to events outside what GitHub Actions triggers cover (e.g. polling, scheduled cross-repo analysis), a persistent service would become necessary.

---

### 2. Severity and Confidence as independent axes (not one merged score)

**Decision:** Semgrep's Severity (deterministic, from rule metadata) and the LLM's Confidence (contextual judgment) are two separate fields, combined via an explicit 12-cell lookup matrix — not merged into one "risk score."

**Alternatives considered:** A single combined score (e.g. weighted average of severity + confidence) that maps directly to an action.

**Why this one:** They measure fundamentally different things. Severity = cost of being wrong if ignored. Confidence = likelihood the finding is actually real. Merging them into one number destroys information — a High-severity/Low-confidence case and a Medium-severity/Medium-confidence case could produce the same merged score but need completely different handling (the former is exactly the override-eligible case; the latter isn't). This was flagged explicitly as an earlier design mistake before being corrected.

**What would change my mind:** Nothing currently — this is a structural property of the problem, not a tuning choice.

---

### 3. Override eligibility restricted to Critical/Low and High/Low confidence cells

**Decision:** Of the 12 matrix cells, only 2 allow a human override via slash command: (Critical, Low confidence) and (High, Low-confidence).

**Alternatives considered:**
- Allow override on any Block Build cell (i.e. also Critical/Medium, Critical/High, High/Medium, High/High).
- Allow override based on severity alone, ignoring confidence.
- Allow override based on confidence alone, ignoring severity.

**Why this one:** The general rule — override eligibility is where automated systems disagree under high-risk conditions: severity says "this could be very bad," confidence says "but I'm not sure it's real." That's the ONLY place a human's judgment adds information the system doesn't already have. When severity is high AND confidence is also high/medium (the model itself supports the finding), overriding would mean bypassing a well-supported security gate on human say-so alone — not what this system is for. When severity is low/medium, there's no need for a formal override process at all; normal review or informational reporting is enough (Build Pass / Manual Review already handle it, per the matrix). It is the CONJUNCTION of high severity + low confidence that matters, not either alone.

**What would change my mind:** Real audit data showing the Medium-confidence threshold is miscalibrated (see #4 below) — that would move which cells are "Low" in the first place, not the eligibility rule itself.

---

### 4. Medium confidence = no override (gate stays strict), and this threshold is tunable policy

**Decision:** At High or Critical severity, Medium confidence still means Block Build with no override — only Low confidence unlocks override eligibility.

**Alternatives considered:** Loosen the line so Medium confidence is also override-eligible.

**Why this one:** Low confidence means the LLM lacks sufficient evidence to judge — genuine uncertainty. Medium confidence means the LLM has enough contextual evidence to support Semgrep's finding, even with some residual uncertainty — the combined evidence (deterministic scanner + contextual reasoning, both pointing the same way) is treated as sufficient to enforce the gate. This is explicitly a POLICY decision, not a hardcoded assumption — for the MVP, "Medium is sufficient" balances security against developer productivity. If audit data later shows Medium-confidence findings are frequently overridden or turn out to be false positives, this threshold should move. The matrix is a configurable risk policy, not a law of nature.

**What would change my mind:** Audit-service data showing Medium-confidence findings have a high false-positive rate in practice.

---

### 5. LLM provider: Gemini Flash (Google AI Studio free tier)

**Decision:** Use Gemini Flash via the free tier for both LLM call sites (initial judgment + expanded-context judgment).

**Alternatives considered:**
- Claude (Anthropic API) — rejected for now: not actually free, requires paid billing even at the cheapest tier (Haiku). Initially considered under a mistaken assumption that Haiku was free — corrected mid-decision.
- GPT-4o-mini / other paid-but-cheap APIs — same free-tier constraint issue.
- Groq (free tier, open-weight models) — viable alternative not yet evaluated in depth.

**Why this one:** Derived from explicit requirements first, provider second: (1) reliable structured/JSON output for programmatic parsing by the Decision Engine, (2) strong-enough contextual reasoning to distinguish test vs. prod secrets, (3) large enough context window for the expanded-context call (multiple files, imports, diffs), (4) low latency — this blocks a CI pipeline, (5) cost — for a personal/student project, "genuinely free" is a hard constraint, not just "cheap," (6) stable production-ready API. Gemini Flash's free tier satisfies all of these; it was chosen against the requirements list, not chosen first and rationalized after.

**Honest tradeoff accepted:** A free/smaller model likely makes more mistakes on hard context-dependent judgment calls (e.g. a dummy credential spread across multiple config files) than a larger paid model (GPT-4/Claude Sonnet+). Accepted because the primary goal is demonstrating the architecture and reasoning pipeline, not maximizing detection accuracy at any cost. This is why the LLM Client is isolated behind the `LLMAssessment` contract in models.py/llm_client.py — swapping providers later means writing one new adapter class, not touching the Decision Engine or anything downstream.

**Caveat — this claim is currently ASPIRATIONAL, not proven:** The model-agnostic design is structurally true (nothing downstream imports Gemini-specific types), but has not actually been tested by swapping in a second provider. Don't claim this as an already-validated property until that's actually been done once.

**What would change my mind:** An actual evaluation (see #7, test-set construction) showing Gemini Flash's false-positive/false-negative rate is unacceptably high on realistic cases — at that point, swapping to a paid model becomes justified by evidence, not just "paid is probably better."

---

### 6. One Python process with internal modules, not separate microservices

**Decision:** Git Operations, Context Processing, Prompt Builder, LLM Client, and Decision Engine are modules/functions within a single Python application that runs as one step inside the GitHub Actions job — not independently deployed services communicating over a network.

**Alternatives considered:** Splitting these into separate services (e.g. each behind its own REST API), which is what an earlier draft of the stack table implied by listing "Python" three times as if they were separate components.

**Why this one:** These modules are tightly coupled and always execute together, sequentially, within a single GitHub Actions run. Splitting them into microservices would require inter-service auth, network calls, separate deployment, and error handling across service boundaries — real architectural cost with zero benefit at this scale. The component boundary that actually matters here is "the Python application" as a whole; Git Operations / Context Processing / Prompt Builder are internal responsibilities within it, not architectural components in their own right.

**What would change my mind:** If the project scaled to support multiple scanners running in parallel, or needed independent scaling of one stage (e.g. LLM calls becoming a bottleneck across many repos), extracting specific modules into real services would become justified.

---

### 7. Audit Service auth: API key for MVP, GitHub OIDC for production

**Decision:** The workflow authenticates to the external Audit Service using a static API key stored in GitHub Secrets, for the MVP. Production deployment would switch to GitHub OIDC (short-lived, signed JWT per workflow run, verified against GitHub's public keys — no long-lived secret to steal).

**Alternatives considered:** Using OIDC from the start.

**Why API key for MVP (not just "it's simpler"):** Verified GitHub's actual default behavior first, rather than assuming: workflows triggered by `pull_request` (not `pull_request_target`) do NOT expose repository secrets to runs originating from fork PRs, by default. This mitigates the highest-risk scenario (a malicious fork PR exfiltrating the audit API key). Combined with least-privilege scoping of the key (it can only write to the audit service, nothing else), the residual risk was evaluated as acceptable for a prototype whose goal is validating the reasoning pipeline, not hardening production auth. This is a scoped, risk-evaluated decision — not "easier to build" as a first instinct.

**Explicit gate on trigger type:** If the workflow trigger is ever changed to `pull_request_target` (sometimes done to get write permissions or secrets access on fork PRs), this entire risk analysis is invalidated and OIDC becomes mandatory, not optional. Noted directly in the workflow YAML comment so this isn't silently forgotten later.

**What would change my mind:** Any production deployment, or any change to the trigger type. OIDC removes the long-lived-secret risk category entirely and is the correct answer once complexity is justified by real stakes.

---

### 8. Fail-safe (not fail-open) on malformed LLM responses

**Decision:** If the LLM's response can't be parsed into a valid `LLMAssessment` (bad JSON, missing fields, invalid enum value), the system defaults to `Confidence.LOW` rather than silently dropping the finding or defaulting to a "safe-looking" high confidence.

**Alternatives considered:** Retry the LLM call; default to Medium confidence; fail the whole workflow run.

**Why this one:** A malformed response must never silently become "Build Pass" — that would mean a parsing bug quietly disables the security gate. Defaulting to Low confidence means: at High/Critical severity, it still routes to at least Manual Review (or stays Block Build, per the matrix) — the system fails toward more human scrutiny, not less, when it doesn't understand its own LLM's output.

**Open question, not yet resolved:** Whether "assume worst case on parse failure" is actually right in practice, or whether it'll prove too noisy (e.g. if Gemini's free tier has a non-trivial malformed-response rate, this could flood Manual Review with parse failures rather than real findings). Flagged in `llm_client.py` as something to revisit once there's real failure data.

**What would change my mind:** Observed parse-failure rate in practice, once the system is actually run against real PRs.

---

### 9. Shared Data Contracts (`app/models.py`) using Pydantic v2

**Decision:** Shared data contracts are defined in `app/models.py` using Pydantic v2 (`BaseModel`) and Python enums (`Severity`, `Confidence`, `Action`).

**Alternatives considered:** Python standard `dataclasses`, `TypedDict`, Pydantic v1.

**Why this one:** Provides strict runtime validation, high-performance CPython/Rust internals, native JSON schema support, and clean syntax for optional/default fields.

**What would change my mind:** Nothing currently — Pydantic v2 is the standard for typed Python data contracts.

---

### 10. Flagged code read directly from git checkout (`pad=0`), bypassing Semgrep's "requires login" JSON truncation

**Decision:** `build_initial_context` reads the actual flagged code snippet directly from the local repository using `GitOps.read_lines_around(file_path, start_line, end_line, pad=0)` instead of relying on `finding.matched_code` from Semgrep's `--json` output.

**Alternatives considered:** Trusting Semgrep's `matched_code` / `extra.lines` field directly.

**Why this one:** Testing against real Semgrep OSS CLI output revealed that community/registry rules omit actual matched lines for unauthenticated scans, returning the literal string `"requires login"`. Relying on `matched_code` would silently pass `"requires login"` into the LLM prompt, degrading the core value proposition of contextual code analysis.

**What would change my mind:** If Semgrep OSS guaranteed un-truncated snippet extraction for all rules in unauthenticated mode in a future CLI release.

---

### 11. Diff-scoped Semgrep scanning for PR CI runs (`git_ops.get_changed_files`)

**Decision:** The main pipeline runs Semgrep strictly on files modified in the PR (`git diff --name-only origin/{base_ref}...HEAD`), rather than scanning the entire repository tree.

**Alternatives considered:** Scan the full codebase on every PR run.

**Why this one:** PR security checks should evaluate changes introduced by the PR. Full-repo scanning adds unnecessary runtime overhead to CI runs and risks blocking PRs due to pre-existing legacy issues outside the PR's scope. 

**What would change my mind:** If cross-file structural or architectural rules are added that require full-codebase context during static scanning, or if security policy requires full repository regression scans on every PR.

---

### 12. Per-finding failure isolation in pipeline orchestration (`app/main.py`)

**Decision:** Processing for each Semgrep finding inside `main.py` is wrapped in an isolated `try/except` block. If processing one finding raises an exception (e.g. LLM rate limit, git error, parse failure), it creates a fallback error result record and allows processing of remaining findings to continue.

**Alternatives considered:** Fail the entire pipeline execution on the first finding error.

**Why this one:** In a multi-finding PR scan, an failure analyzing one finding (such as a transient API error or edge-case parse issue) should not hide or cancel evaluation of other valid findings. Isolating failures ensures max visibility into security risks across the entire PR.

**What would change my mind:** If an infrastructure error occurs prior to the finding processing loop (e.g., missing mandatory environment variables or git repository corruption), where failing fast at the top level is mandatory.

---

### 13. Prompt definition: Confidence measures Genuine Risk Probability, not reasoning self-certainty (`app/prompt_builder.py`)

**Decision:** The prompt explicitly instructs the LLM that `confidence` represents how confident it is that the finding is a *GENUINE, real, exploitable secret or vulnerability* (High = real vulnerability, Low = test fixture / mock / dummy data / false positive), rather than confidence in its own internal reasoning process.

**Alternatives considered:** Allow the LLM to output "High confidence" when it is 100% sure a snippet is a test fixture.

**Why this one:** In early design, models could mark test fixtures with "High confidence" (meaning high certainty in their assessment that it's a test file). However, the Decision Engine matrix relies on `Confidence` as the probability of genuine risk. If a test fixture produces `(High severity, High confidence)` from the LLM, the matrix would trigger a `Block Build` action — defeating the primary purpose of SentinelCI. Defining confidence as risk probability aligns prompt outputs with matrix semantics.

**What would change my mind:** If the schema were redesigned to separate `Is_False_Positive` (boolean) from `Model_Self_Certainty` (enum), which would require changing the model contracts and matrix lookup logic.

---

### 14. Strict single-pass context expansion cap (1 retry max) (`app/main.py`)

**Decision:** When `LLMAssessment.context_sufficient == False`, SentinelCI performs `expand_context` and queries the LLM exactly once more — enforcing a hard cap of 1 retry.

**Alternatives considered:** Loop until `context_sufficient == True` or a higher retry limit is reached.

**Why this one:** If a code snippet remains ambiguous to the LLM even after surrounding context expansion, repeated queries are unlikely to yield new insight and risk causing CI timeouts or API rate-limit exhaustion. A single expansion pass balances context completeness against pipeline latency and resource cost.

**What would change my mind:** Real audit data showing that 2-stage context expansion (e.g., expanding related files in a second pass) significantly improves assessment accuracy without causing pipeline degradation.

---

*(This file is appended to after each build step — not a one-time document.)*

