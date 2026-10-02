-- +goose Up
CREATE TABLE assets (
    id         bigserial PRIMARY KEY,
    kind       text        NOT NULL,
    key        text        NOT NULL,
    source     text        NOT NULL DEFAULT '',
    scope      text        NOT NULL DEFAULT '',
    zone       text        NOT NULL DEFAULT '',
    attrs      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    removed_at timestamptz,
    CONSTRAINT assets_kind_key_uniq UNIQUE (kind, key)
);
CREATE INDEX assets_source_live_idx ON assets (source) WHERE removed_at IS NULL;
CREATE INDEX assets_zone_idx ON assets (zone);
CREATE INDEX assets_scope_idx ON assets (scope);

CREATE TABLE relations (
    from_id bigint NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    to_id   bigint NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    type    text   NOT NULL,
    PRIMARY KEY (from_id, to_id, type)
);
CREATE INDEX relations_to_idx ON relations (to_id);

CREATE TABLE observations (
    asset_id    bigint      NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    check_name  text        NOT NULL,
    data        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, check_name)
);

CREATE TABLE baselines (
    asset_id   bigint      NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    check_name text        NOT NULL,
    data       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    stable     boolean     NOT NULL DEFAULT false,
    consistent integer     NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, check_name)
);

CREATE TABLE findings (
    id               bigserial PRIMARY KEY,
    fingerprint      text        NOT NULL,
    check_name       text        NOT NULL,
    asset_id         bigint      NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    severity         text        NOT NULL,
    severity_rank    smallint    NOT NULL,
    title            text        NOT NULL DEFAULT '',
    description      text        NOT NULL DEFAULT '',
    evidence         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    remediation      text        NOT NULL DEFAULT '',
    tags             text[]      NOT NULL DEFAULT '{}',
    status           text        NOT NULL,
    first_seen       timestamptz NOT NULL,
    last_seen        timestamptz NOT NULL,
    resolved_at      timestamptz,
    missed_runs      integer     NOT NULL DEFAULT 0,
    reopened_count   integer     NOT NULL DEFAULT 0,
    suppressed_until timestamptz,
    suppression_note text        NOT NULL DEFAULT '',
    status_actor     text        NOT NULL DEFAULT '',
    CONSTRAINT findings_fingerprint_uniq UNIQUE (fingerprint)
);
CREATE INDEX findings_status_sev_idx ON findings (status, severity_rank DESC);
CREATE INDEX findings_asset_check_idx ON findings (asset_id, check_name);
CREATE INDEX findings_resolved_at_idx ON findings (resolved_at) WHERE status = 'resolved';
CREATE INDEX findings_suppressed_until_idx ON findings (suppressed_until)
    WHERE suppressed_until IS NOT NULL AND status IN ('suppressed', 'acknowledged');

CREATE TABLE events (
    id      bigserial PRIMARY KEY,
    type    text        NOT NULL,
    subject text        NOT NULL,
    data    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    at      timestamptz NOT NULL
);
CREATE INDEX events_at_idx ON events (at DESC, id DESC);

CREATE TABLE syncs (
    source      text PRIMARY KEY,
    type        text        NOT NULL DEFAULT '',
    last_run    timestamptz NOT NULL,
    last_ok     timestamptz,
    error       text        NOT NULL DEFAULT '',
    asset_count integer     NOT NULL DEFAULT 0,
    duration_ms bigint      NOT NULL DEFAULT 0
);

CREATE TABLE scans (
    id          bigserial PRIMARY KEY,
    asset_id    bigint      NOT NULL,
    check_name  text        NOT NULL,
    tier        text        NOT NULL DEFAULT '',
    started_at  timestamptz NOT NULL,
    duration_ms bigint      NOT NULL DEFAULT 0,
    error       text        NOT NULL DEFAULT '',
    findings    integer     NOT NULL DEFAULT 0
);
CREATE INDEX scans_started_idx ON scans (started_at DESC, id DESC);

-- +goose Down
DROP TABLE scans;
DROP TABLE syncs;
DROP TABLE events;
DROP TABLE findings;
DROP TABLE baselines;
DROP TABLE observations;
DROP TABLE relations;
DROP TABLE assets;
