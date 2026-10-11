-- SentinelCI Audit Service schema
-- Designed for PostgreSQL (Neon-compatible)

CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL       PRIMARY KEY,

    -- PR context
    repo            TEXT            NOT NULL,
    pr_number       INTEGER         NOT NULL,
    commit_sha      TEXT            NOT NULL,

    -- Finding location & identity
    file_path       TEXT            NOT NULL,
    line            INTEGER,
    rule_id         TEXT            NOT NULL,
    -- code_hash (not line number) is part of the dedupe key because line numbers
    -- shift when unrelated lines are added above a finding; a content hash stays
    -- stable and lets the same finding keep its ID across pushes (architecture.md §4).
    code_hash       TEXT            NOT NULL,

    -- Assessment
    severity        TEXT            NOT NULL,
    confidence      TEXT            NULL,       -- NULL allowed: ERROR records have no confidence
    category        TEXT            NULL,
    action          TEXT            NOT NULL,
    reasoning       TEXT            NULL,

    -- Override
    override_eligible BOOLEAN       NOT NULL DEFAULT FALSE,
    status          TEXT            NOT NULL DEFAULT 'open',   -- values: open, overridden
    override_by     TEXT            NULL,
    override_reason TEXT            NULL,
    override_at     TIMESTAMPTZ    NULL,

    -- Timestamps
    first_seen_at   TIMESTAMPTZ    NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ    NOT NULL DEFAULT now(),

    -- Dedupe key: same finding keeps its ID across pushes (architecture.md §4).
    -- Uses code_hash instead of line number — see comment on code_hash column above.
    UNIQUE (repo, pr_number, file_path, rule_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings (repo);
