package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

const outboxBatchSize = 100

// RunOutboxRelay drains auth.outbox to Kafka until ctx is cancelled. Events
// are produced in commit (id) order and only marked published after Kafka
// acknowledges them, giving at-least-once delivery: a crash between produce
// and mark re-sends on the next tick, so consumers must be idempotent.
func (a *Server) RunOutboxRelay(ctx context.Context, interval time.Duration) {
	if a.producer == nil {
		slog.Warn("outbox relay not started: kafka disabled; events will accumulate in auth.outbox")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.runOutboxRelay(ctx, ticker.C)
}

func (a *Server) runOutboxRelay(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			a.drainOutbox(ctx)
		}
	}
}

func (a *Server) drainOutbox(ctx context.Context) {
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		full, err := a.relayBatch(batchCtx)
		cancel()
		if err != nil {
			// Shutdown is not an error; anything else is reported and
			// retried on the next tick.
			if ctx.Err() == nil {
				a.reportBackground(ctx, "outbox_relay", "relay", slog.LevelError, err, "")
			}
			return
		}
		if !full {
			return // drained, or stopped early to preserve ordering
		}
	}
}

// relayBatch publishes one batch. It returns true when the batch was full and
// fully delivered, meaning more rows may be waiting.
func (a *Server) relayBatch(ctx context.Context) (bool, error) {
	rows, err := a.db.FetchUnpublishedOutbox(ctx, outboxBatchSize)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}

	published := make([]int64, 0, len(rows))
	var produceErr error
	for _, row := range rows {
		// json.RawMessage round-trips the stored payload byte-for-byte.
		if err := a.producer.Produce(ctx, row.Topic, []byte(row.Key), json.RawMessage(row.Payload), row.Headers); err != nil {
			// Stop at the first failure so per-user event ordering is
			// preserved; the remainder retries on the next tick.
			produceErr = err
			break
		}
		published = append(published, row.ID)
	}

	if len(published) > 0 {
		if err := a.db.MarkOutboxPublished(ctx, published); err != nil {
			return false, err
		}
	}
	if produceErr != nil {
		return false, produceErr
	}

	return len(rows) == outboxBatchSize, nil
}
