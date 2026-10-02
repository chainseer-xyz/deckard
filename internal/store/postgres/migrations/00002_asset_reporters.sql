-- +goose Up
-- reporters is the set of inventory sources whose latest snapshot reported the
-- asset. An asset is removed only when no source reports it any more. Derived
-- assets (found by checks) have no reporters.
ALTER TABLE assets ADD COLUMN reporters text[] NOT NULL DEFAULT '{}';
UPDATE assets SET reporters = ARRAY[source]
 WHERE removed_at IS NULL
   AND source NOT IN ('', 'discovered')
   AND source NOT LIKE 'check:%'
   AND source NOT LIKE 'net.%'
   AND source NOT LIKE 'expansion:%';

-- +goose Down
ALTER TABLE assets DROP COLUMN reporters;
