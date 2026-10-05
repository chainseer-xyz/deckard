-- +goose Up
-- Scheduling survives scan-history retention and process/replica changes.
CREATE TABLE scan_state (
    asset_id     bigint NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    check_name   text NOT NULL,
    last_attempt timestamptz NOT NULL,
    last_success timestamptz,
    PRIMARY KEY (asset_id, check_name)
);
INSERT INTO scan_state (asset_id, check_name, last_attempt, last_success)
SELECT asset_id, check_name, max(started_at),
       max(started_at) FILTER (WHERE error = '' OR starts_with(error, 'skipped: unowned destination: '))
FROM scans GROUP BY asset_id, check_name;

-- +goose Down
DROP TABLE scan_state;
