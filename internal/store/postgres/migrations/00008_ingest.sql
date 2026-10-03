-- Findings reported by external scanners through POST /api/v1/ingest.
--
-- findings.ingest_scope is the scanned scope (account/region, cluster, org) an
-- ingested finding belongs to; '' for findings of built-in checks. An ingest
-- reconciles every finding of (check_name, ingest_scope), whatever asset it is
-- attached to, so that pair is indexed.
--
-- findings.source overrides the asset's source as the finding's source label
-- ('' keeps the asset's): an ingested finding attached to an existing asset of
-- another source still reports source = ingest:<tool>.
--
-- ingest_scopes holds per (tool, scope) state: the digest of the last accepted
-- request (a retried delivery is a no-op), the newest observed_at (an older run
-- never resolves anything) and freshness for metrics.
--
-- Every statement is idempotent so the migration is safe on a database that
-- already has these objects.
-- +goose Up
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ingest_scope text NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS findings_ingest_scope_idx ON findings (check_name, ingest_scope) WHERE ingest_scope <> '';

CREATE TABLE IF NOT EXISTS ingest_scopes (
    tool             text        NOT NULL,
    scope            text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_at          timestamptz NOT NULL,
    complete_at      timestamptz,
    observed_at      timestamptz NOT NULL,
    last_digest      text        NOT NULL DEFAULT '',
    PRIMARY KEY (tool, scope)
);

-- +goose Down
DROP TABLE IF EXISTS ingest_scopes;
DROP INDEX IF EXISTS findings_ingest_scope_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS source;
ALTER TABLE findings DROP COLUMN IF EXISTS ingest_scope;
