-- +goose Up
CREATE TABLE IF NOT EXISTS scan_triggers (
    key text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('templates', 'kev')),
    templates text[] NOT NULL DEFAULT '{}',
    cves text[] NOT NULL DEFAULT '{}',
    release text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz
);
CREATE INDEX IF NOT EXISTS scan_triggers_pending_idx
    ON scan_triggers (kind, created_at, key) WHERE acknowledged_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS scan_triggers;
