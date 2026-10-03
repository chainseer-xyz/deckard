-- Liveness of the engine's River clients. River (as vendored) keeps no client
-- heartbeat, so a job left 'running' by a crashed or SIGKILLed instance stays
-- running until River's rescuer gives up on it (RescueStuckJobsAfter). Each
-- worker/scheduler instance registers its River client id here and refreshes
-- seen_at every few seconds; peers move the running jobs of an instance that
-- has stopped heartbeating back to retryable. See internal/engine/instances.go.
-- +goose Up
CREATE TABLE IF NOT EXISTS deckard_instances (
    client_id  text        PRIMARY KEY,
    started_at timestamptz NOT NULL DEFAULT now(),
    seen_at    timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS deckard_instances;
