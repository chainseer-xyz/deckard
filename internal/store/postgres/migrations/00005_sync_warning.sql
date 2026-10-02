-- +goose Up
ALTER TABLE syncs ADD COLUMN warning text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE syncs DROP COLUMN warning;
