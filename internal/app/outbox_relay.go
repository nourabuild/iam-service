package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

const outboxBatchSize = 100

// RunOutboxRelay drains auth.outbox to Kafka until ctx is cancelled. Events
// are produced in commit (id) order and only marked published after Kafka
// acknowledges them, giving at-least-once delivery: a crash between produce
// and mark re-sends on the next tick, so consumers must be idempotent.
func (a *App) RunOutboxRelay(ctx context.Context, interval time.Duration) {
	if a.kafka == nil {
		slog.Warn("outbox relay not started: kafka disabled; events will accumulate in auth.outbox until kafka returns")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.drainOutbox(ctx)
		}
	}
}

func (a *App) drainOutbox(ctx context.Context) {
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		full, err := a.relayBatch(batchCtx)
		cancel()
		if err != nil {
			// Shutdown is not an error; anything else is reported and
			// retried on the next tick.
			if ctx.Err() == nil {
				a.toSentryBackground("outbox_relay", "relay", sentry.LevelError, err, "")
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
func (a *App) relayBatch(ctx context.Context) (bool, error) {
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
		headers := make([]kafka.RecordHeader, 0, len(row.Headers))
		for k, v := range row.Headers {
			headers = append(headers, kafka.RecordHeader{Key: k, Value: []byte(v)})
		}

		// json.RawMessage round-trips the stored payload byte-for-byte.
		if err := a.kafka.Produce(ctx, row.Topic, []byte(row.Key), json.RawMessage(row.Payload), headers...); err != nil {
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
