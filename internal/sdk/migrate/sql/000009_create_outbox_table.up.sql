-- Transactional outbox: user lifecycle events are inserted here in the same
-- transaction as the user mutation, then relayed to Kafka by a background
-- loop. This guarantees at-least-once delivery — an event row either commits
-- with its mutation or not at all, and survives Kafka outages and restarts.
-- Consumers must be idempotent (events carry user_id + occurred_at).
CREATE TABLE IF NOT EXISTS auth.outbox (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    topic TEXT NOT NULL,
    key TEXT NOT NULL,
    payload JSONB NOT NULL,
    headers JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMPTZ
);

-- The relay only ever scans unpublished rows in id order.
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON auth.outbox (id) WHERE published_at IS NULL;
