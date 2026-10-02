-- +goose Up
CREATE INDEX scans_asset_check_started_idx ON scans (asset_id, check_name, started_at DESC);

-- +goose Down
DROP INDEX scans_asset_check_started_idx;
