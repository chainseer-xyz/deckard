-- +goose Up
-- Relationships may disappear while their endpoints remain live.
-- Drain row-locking inventory writers before adding/backfilling foreign keys.
-- Their parent FOR UPDATE -> asset INSERT order otherwise deadlocks with the
-- weaker lock taken by FK creation. EXCLUSIVE still allows ordinary reads.
LOCK TABLE assets IN EXCLUSIVE MODE;
CREATE TABLE relation_reporters (
    from_id  bigint NOT NULL,
    to_id    bigint NOT NULL,
    type     text   NOT NULL,
    reporter text   NOT NULL,
    parent_id bigint REFERENCES assets (id) ON DELETE CASCADE,
    PRIMARY KEY (from_id, to_id, type, reporter),
    FOREIGN KEY (from_id, to_id, type) REFERENCES relations (from_id, to_id, type) ON DELETE CASCADE
);
CREATE INDEX relation_reporters_reporter_idx ON relation_reporters (reporter);
CREATE INDEX relation_reporters_parent_idx ON relation_reporters (parent_id) WHERE parent_id IS NOT NULL;

-- Each source's next complete snapshot confirms or retires recovered edges.
INSERT INTO relation_reporters (from_id, to_id, type, reporter)
SELECT r.from_id, r.to_id, r.type, 'source:' || src
FROM relations r JOIN assets f ON f.id = r.from_id JOIN assets t ON t.id = r.to_id
CROSS JOIN LATERAL unnest(f.reporters) AS src
WHERE src = ANY(t.reporters)
ON CONFLICT DO NOTHING;

INSERT INTO relation_reporters (from_id, to_id, type, reporter, parent_id)
SELECT r.from_id, r.to_id, r.type, 'check:' || d.parent_id::text || ':' || d.origin, d.parent_id
FROM relations r JOIN derivations d
ON (r.from_id = d.parent_id AND r.to_id = d.child_id)
OR (r.to_id = d.parent_id AND r.from_id = d.child_id)
ON CONFLICT DO NOTHING;

-- Parentless discovery has no replaceable snapshot. Endpoint retention owns it.
INSERT INTO relation_reporters (from_id, to_id, type, reporter)
SELECT r.from_id, r.to_id, r.type, 'discovered'
FROM relations r WHERE NOT EXISTS (
    SELECT 1 FROM relation_reporters p
    WHERE p.from_id = r.from_id AND p.to_id = r.to_id AND p.type = r.type
);

-- +goose Down
DROP TABLE relation_reporters;
