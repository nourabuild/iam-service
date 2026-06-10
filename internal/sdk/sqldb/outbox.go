package sqldb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

// OutboxEventFunc builds the outbox message announcing a user mutation, from
// the row the mutation returned. A nil func (or nil return) means no event.
type OutboxEventFunc func(models.User) *models.OutboxMessage

// querier is the subset of *sql.DB / *sql.Tx the mutation closures need, so
// the same query code runs standalone or inside an outbox transaction.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// mutateWithOutbox runs a user mutation and, when eventFn is provided, writes
// the event it builds to auth.outbox in the same transaction. Either both the
// mutation and its event commit, or neither does — the relay then guarantees
// at-least-once delivery to Kafka.
func (s *service) mutateWithOutbox(ctx context.Context, eventFn OutboxEventFunc, mutate func(querier) (models.User, error)) (models.User, error) {
	if eventFn == nil {
		return mutate(s.db)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.User{}, fmt.Errorf("beginning outbox tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	user, err := mutate(tx)
	if err != nil {
		return models.User{}, err
	}

	if msg := eventFn(user); msg != nil {
		if err := insertOutbox(ctx, tx, *msg); err != nil {
			return models.User{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return models.User{}, fmt.Errorf("committing outbox tx: %w", err)
	}

	return user, nil
}

func insertOutbox(ctx context.Context, q querier, msg models.OutboxMessage) error {
	const query = `
		INSERT INTO auth.outbox (topic, key, payload, headers)
		VALUES ($1, $2, $3, $4)
	`

	payload, err := json.Marshal(msg.Payload)
	if err != nil {
		return fmt.Errorf("marshaling outbox payload: %w", err)
	}

	var headers []byte
	if len(msg.Headers) > 0 {
		if headers, err = json.Marshal(msg.Headers); err != nil {
			return fmt.Errorf("marshaling outbox headers: %w", err)
		}
	}

	if _, err := q.ExecContext(ctx, query, msg.Topic, msg.Key, payload, headers); err != nil {
		return fmt.Errorf("inserting outbox message: %w", err)
	}

	return nil
}

// FetchUnpublishedOutbox returns up to limit pending events in commit order.
func (s *service) FetchUnpublishedOutbox(ctx context.Context, limit int) ([]models.OutboxRow, error) {
	const query = `
		SELECT id, topic, key, payload, headers, created_at
		FROM auth.outbox
		WHERE published_at IS NULL
		ORDER BY id
		LIMIT $1
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("fetching outbox: %w", err)
	}
	defer rows.Close()

	var out []models.OutboxRow
	for rows.Next() {
		var row models.OutboxRow
		var headers []byte
		if err := rows.Scan(&row.ID, &row.Topic, &row.Key, &row.Payload, &headers, &row.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning outbox row: %w", err)
		}
		if len(headers) > 0 {
			if err := json.Unmarshal(headers, &row.Headers); err != nil {
				return nil, fmt.Errorf("unmarshaling outbox headers: %w", err)
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating outbox rows: %w", err)
	}

	return out, nil
}

// MarkOutboxPublished stamps the given events as delivered.
func (s *service) MarkOutboxPublished(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	const query = `
		UPDATE auth.outbox
		SET published_at = CURRENT_TIMESTAMP
		WHERE id = ANY($1)
	`

	if _, err := s.db.ExecContext(ctx, query, ids); err != nil {
		return fmt.Errorf("marking outbox published: %w", err)
	}

	return nil
}

// DeletePublishedOutbox removes delivered events older than the retention
// window, bounding table growth.
func (s *service) DeletePublishedOutbox(ctx context.Context, olderThan time.Duration) error {
	const query = `
		DELETE FROM auth.outbox
		WHERE published_at IS NOT NULL
		AND published_at < $1
	`

	if _, err := s.db.ExecContext(ctx, query, time.Now().UTC().Add(-olderThan)); err != nil {
		return fmt.Errorf("deleting published outbox messages: %w", err)
	}

	return nil
}
