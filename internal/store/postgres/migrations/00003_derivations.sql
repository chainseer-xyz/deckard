-- +goose Up
-- derivations records which check (origin) observed a derived child asset while
-- scanning a parent asset, so a child can be garbage-collected when no
-- (parent, origin) observes it any more.
CREATE TABLE derivations (
    child_id  bigint NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    parent_id bigint NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    origin    text   NOT NULL,
    PRIMARY KEY (child_id, parent_id, origin)
);
CREATE INDEX derivations_parent_idx ON derivations (parent_id, origin);

-- +goose Down
DROP TABLE derivations;
