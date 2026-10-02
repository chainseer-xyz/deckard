-- The fingerprint hashes (check, asset key, finding key) — not the asset
-- KIND — so a zone asset and its apex hostname asset (both exist whenever an
-- apex DNS record is inventoried) produce the same fingerprint for the same
-- finding of a kind-agnostic check such as dns.dangling. With a global
-- unique constraint the second asset's reconcile fails permanently on
-- insert. Deduplication was always per asset (reconcile loads existing
-- findings by asset_id + check), so scope the constraint accordingly.
-- +goose Up
ALTER TABLE findings DROP CONSTRAINT findings_fingerprint_uniq;
ALTER TABLE findings ADD CONSTRAINT findings_asset_fingerprint_uniq UNIQUE (asset_id, fingerprint);

-- +goose Down
ALTER TABLE findings DROP CONSTRAINT findings_asset_fingerprint_uniq;
ALTER TABLE findings ADD CONSTRAINT findings_fingerprint_uniq UNIQUE (fingerprint);
