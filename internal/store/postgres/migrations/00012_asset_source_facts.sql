-- +goose Up
-- The first statement's ACCESS EXCLUSIVE lock drains existing writers before
-- backfill. No secondary metadata survived in the old schema; do not invent it
-- by copying the canonical source's fields into other reporters' facts.
ALTER TABLE assets ADD COLUMN source_facts jsonb NOT NULL DEFAULT '{}';
UPDATE assets SET source_facts = jsonb_build_object(source,
    (CASE WHEN zone = '' THEN '{}'::jsonb ELSE jsonb_build_object('zone', zone) END) ||
    (CASE WHEN attrs = '{}'::jsonb THEN '{}'::jsonb ELSE jsonb_build_object('attrs', attrs) END))
 WHERE removed_at IS NULL
   AND source = ANY(reporters)
   AND source NOT IN ('', 'discovered')
   AND source NOT LIKE 'check:%'
   AND source NOT LIKE 'net.%'
   AND source NOT LIKE 'expansion:%';

-- +goose Down
ALTER TABLE assets DROP COLUMN source_facts;
