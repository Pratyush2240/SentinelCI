# Architecture & Design Decisions Log — SentinelCI

This document tracks all key architectural, technical, and design decisions made throughout the development of SentinelCI. It documents the rationale behind choices, alternative options considered, and the trade-offs evaluated.

---

## Record of Decisions

### Decision 1: Shared Data Contracts Layer (`app/models.py`) using Pydantic v2
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: SentinelCI requires strict data standardizations between static analysis tools (Semgrep), context extractors, LLM reasoning adapters, policy engines, and audit logger modules.
- **Decision**: Define shared data contracts using **Pydantic v2 (`BaseModel`)** in a standalone file `app/models.py` with `from __future__ import annotations`.
- **Options Considered**:
  1. *Python Standard `dataclasses`*: Lightweight, built-in, but lacks built-in type validation, automatic JSON schema generation, and robust serialization/deserialization methods required when interfacing with external CLI tools and LLM JSON APIs.
  2. *`TypedDict`*: Purely static typing with zero runtime validation or default values.
  3. *Pydantic v1*: Legacy version; slower execution compared to Pydantic v2's Rust core (`pydantic-core`) and lacks V2's improved field validation and serialization model.
  4. *Pydantic v2 (`BaseModel`)*: Chosen option. Provides strict runtime validation, high-performance CPython/Rust internals, native JSON schema support, and clean syntax for optional/default fields.

---

### Decision 2: Strict Separation of `Severity` and `Confidence` Axes
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: Static scanners categorize vulnerability impact, while LLMs evaluate whether a flagged code snippet is a true positive based on surrounding context.
- **Decision**: Maintain `Severity` (deterministic rule metadata from Semgrep) and `Confidence` (LLM contextual judgment) as two completely independent axes.
- **Options Considered**:
  1. *Unified Risk Score (e.g., `Risk = Severity * Confidence`)*: Merges impact and likelihood into a single scalar score.
  2. *Independent Dual Axis (`Severity` Enum + `Confidence` Enum)*: Chosen option.
- **Rationale & Trade-offs**:
  - Combining severity and confidence into a single composite score conceals crucial nuance. For instance, a `CRITICAL` vulnerability (like hardcoded AWS master keys) with `MEDIUM` confidence should not be downgraded to a low-risk score and ignored; it warrants `MANUAL_REVIEW`.
  - Keeping them separate guarantees that deterministic scanner rules are never muted or overwritten by AI hallucination or misclassification.

---

### Decision 3: Provider-Agnostic LLM Assessment Contract (`LLMAssessment`)
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: The LLM reasoning layer needs to work seamlessly across multiple model providers (e.g., OpenAI, Anthropic, Gemini, local Ollama models) without coupling application logic to a specific provider's API.
- **Decision**: Require all provider adapters to return a standardized `LLMAssessment` Pydantic model (`confidence`, `category`, `reasoning`, `context_sufficient`).
- **Options Considered**:
  1. *Provider-specific output dicts*: Allows models to return arbitrary metadata. High coupling; requires downstreams to handle different schema shapes.
  2. *Unified `LLMAssessment` contract*: Chosen option.
- **Rationale**: Shields downstream pipeline stages (Action Engine, Audit Logger) from model vendor changes. Updating or swapping LLM backends requires only writing a new adapter that outputs `LLMAssessment`.

---

### Decision 4: Two-Pass Dynamic Context Retrieval Architecture
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: Semgrep provides line-level matches, but assessing true/false positives often requires context outside the immediate code snippet. However, sending entire repositories on every finding is cost-prohibitive and slow.
- **Decision**: Implement a two-pass context pipeline controlled by `LLMAssessment.context_sufficient` and `ContextBundle.is_expanded`.
  - **Pass 1**: Extract localized context (±50 surrounding lines, enclosing function, nearby comments).
  - **Pass 2 (Conditional)**: If the LLM indicates `context_sufficient=False`, retrieve additional cross-file or project-level context, set `is_expanded=True`, and re-assess.
- **Options Considered**:
  1. *Fixed Single-Pass Context*: Always supply fixed ±5 lines or ±50 lines. Misses inter-file dependencies or global configuration contexts.
  2. *Full Repo Context Always*: Exposes every scan to massive token overhead and API costs.
  3. *Two-Pass Dynamic Context*: Chosen option. Balances latency, token cost, and accuracy.

---

### Decision 5: Explicit Pipeline Action Policy Enum (`Action`)
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: CI/CD security tools need deterministic actions to govern build pipelines (blocking PR merges, requesting review, or allowing pass).
- **Decision**: Define an explicit `Action` enum (`BLOCK_BUILD`, `MANUAL_REVIEW`, `BUILD_PASS`).
- **Options Considered**:
  1. *Boolean Pass/Fail*: Too simplistic; cannot differentiate between clean code and findings requiring human verification.
  2. *Tri-State `Action` Enum*: Chosen option. Enables nuanced CI workflows (e.g. automatic blocking for High Severity + High Confidence, manual review for High Severity + Medium Confidence).

---

### Decision 6: Local Git Checkout Syscalls vs GitHub REST/GraphQL API Calls (`app/git_ops.py`)
- **Date**: 2026-08-30
- **Status**: Accepted
- **Context**: SentinelCI needs to read file contents, extract line ranges around flagged findings, run git blame, and inspect diffs during CI pipeline execution.
- **Decision**: Perform all file reading, line extraction, git blame, and diff operations directly on the local Git checkout cloned by GitHub Actions onto the runner (`pathlib.Path` & `subprocess.run`), avoiding GitHub API calls.
- **Options Considered**:
  1. *GitHub REST / GraphQL API Requests*: Fetch file contents, git blame, and PR diffs over HTTP using GitHub's REST/GraphQL APIs (e.g., PyGithub, Octokit).
  2. *Local Git Checkout Syscalls (`app/git_ops.py`)*: Chosen option.
- **Rationale & Trade-offs**:
  - **Latency**: Local disk reads (`read_text`) and local `git blame` subprocess calls execute in sub-milliseconds to milliseconds, compared to 100–500ms network latency per API request.
  - **Rate Limits**: GitHub API calls are subject to strict rate limits (e.g., 1,000 to 5,000 requests/hour per `GITHUB_TOKEN`). High-volume CI scans on large PRs can easily exhaust API quotas.
  - **Simplicity**: No need for network authentication, API retries, or secret management inside context retrieval modules.

---

### Decision 7: Sibling File Discovery (`find_related_files`) as a Temporary Placeholder Heuristic
- **Date**: 2026-08-30
- **Status**: Temporary Heuristic (Not Final Design Decision)
- **Context**: When an LLM requires expanded context (`context_sufficient=False`), SentinelCI must discover related project files to enrich the `ContextBundle`.
- **Decision**: Implement `find_related_files` using a lightweight sibling file heuristic (up to 5 files in the same directory) and explicitly document it as a temporary placeholder.
- **Options Considered**:
  1. *AST / Language Import Graph Analysis*: Parse import trees (Python AST, TS Compiler API) to discover true cross-file dependencies.
  2. *Git Co-Commit Analysis*: Query `git log` history to identify files frequently committed together.
  3. *Same-Directory Sibling Heuristic*: Chosen placeholder option.
- **Rationale**: Enables building and validating the dynamic context expansion pipeline early without blocking on language-specific AST parser integrations.

