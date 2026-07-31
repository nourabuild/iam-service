package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/kafka"
)

type relayFetchResult struct {
	rows []models.OutboxRow
	err  error
}

type relayDBFake struct {
	sqldb.Service

	fetchResults  []relayFetchResult
	fetchCalls    int
	fetchLimits   []int
	fetchContexts []context.Context
	fetchHook     func(int)

	markCalls [][]int64
	markErr   error
}

func (f *relayDBFake) FetchUnpublishedOutbox(ctx context.Context, limit int) ([]models.OutboxRow, error) {
	call := f.fetchCalls
	f.fetchCalls++
	f.fetchLimits = append(f.fetchLimits, limit)
	f.fetchContexts = append(f.fetchContexts, ctx)
	if f.fetchHook != nil {
		f.fetchHook(call)
	}
	if call >= len(f.fetchResults) {
		return nil, nil
	}
	return f.fetchResults[call].rows, f.fetchResults[call].err
}

func (f *relayDBFake) MarkOutboxPublished(_ context.Context, ids []int64) error {
	f.markCalls = append(f.markCalls, append([]int64(nil), ids...))
	return f.markErr
}

type relayProducedRecord struct {
	ctx     context.Context
	topic   string
	key     []byte
	value   any
	headers []kafka.RecordHeader
}

type relayProducerFake struct {
	records    []relayProducedRecord
	failAt     int
	produceErr error
}

func newRelayProducerFake() *relayProducerFake {
	return &relayProducerFake{failAt: -1}
}

func (f *relayProducerFake) Produce(
	ctx context.Context,
	topic string,
	key []byte,
	value any,
	headers ...kafka.RecordHeader,
) error {
	copiedHeaders := make([]kafka.RecordHeader, len(headers))
	for i, header := range headers {
		copiedHeaders[i] = kafka.RecordHeader{
			Key:   header.Key,
			Value: append([]byte(nil), header.Value...),
		}
	}
	if raw, ok := value.(json.RawMessage); ok {
		value = append(json.RawMessage(nil), raw...)
	}

	f.records = append(f.records, relayProducedRecord{
		ctx:     ctx,
		topic:   topic,
		key:     append([]byte(nil), key...),
		value:   value,
		headers: copiedHeaders,
	})
	if len(f.records)-1 == f.failAt {
		return f.produceErr
	}
	return nil
}

func (*relayProducerFake) Close() {}

func TestRunOutboxRelay(t *testing.T) {
	t.Run("does not start without Kafka", func(t *testing.T) {
		logs := captureDefaultLogs(t)
		app := &App{}

		// A zero interval would panic if the ticker were created.
		app.RunOutboxRelay(context.Background(), 0)

		if !strings.Contains(logs.String(), "outbox relay not started") {
			t.Fatalf("expected Kafka-disabled warning, got %q", logs.String())
		}
	})

	t.Run("returns when context is already canceled", func(t *testing.T) {
		db := &relayDBFake{}
		app := &App{db: db, kafka: newRelayProducerFake()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		app.RunOutboxRelay(ctx, time.Hour)

		if db.fetchCalls != 0 {
			t.Fatalf("expected no fetch after cancellation, got %d", db.fetchCalls)
		}
	})
}

func TestRunOutboxRelayProcessesTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db := &relayDBFake{
		fetchResults: []relayFetchResult{{}},
		fetchHook: func(int) {
			cancel()
		},
	}
	app := &App{db: db, kafka: newRelayProducerFake()}
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()

	app.runOutboxRelay(ctx, ticks)

	if db.fetchCalls != 1 {
		t.Fatalf("expected one fetch for one tick, got %d", db.fetchCalls)
	}
}

func TestDrainOutboxContinuesOnlyAfterFullBatch(t *testing.T) {
	first := makeOutboxRows(outboxBatchSize, 1)
	second := makeOutboxRows(1, int64(outboxBatchSize+1))
	db := &relayDBFake{fetchResults: []relayFetchResult{
		{rows: first},
		{rows: second},
	}}
	producer := newRelayProducerFake()
	app := &App{db: db, kafka: producer}

	app.drainOutbox(context.Background())

	if db.fetchCalls != 2 {
		t.Fatalf("expected two fetches, got %d", db.fetchCalls)
	}
	if !reflect.DeepEqual(db.fetchLimits, []int{outboxBatchSize, outboxBatchSize}) {
		t.Fatalf("unexpected fetch limits: %v", db.fetchLimits)
	}
	if len(producer.records) != outboxBatchSize+1 {
		t.Fatalf("expected %d produced records, got %d", outboxBatchSize+1, len(producer.records))
	}
	if len(db.markCalls) != 2 {
		t.Fatalf("expected two mark calls, got %d", len(db.markCalls))
	}
	assertInt64sEqual(t, db.markCalls[0], outboxIDs(first))
	assertInt64sEqual(t, db.markCalls[1], outboxIDs(second))

	for i, fetchCtx := range db.fetchContexts {
		if _, ok := fetchCtx.Deadline(); !ok {
			t.Errorf("fetch context %d has no deadline", i)
		}
		if !errors.Is(fetchCtx.Err(), context.Canceled) {
			t.Errorf("fetch context %d was not canceled after the batch: %v", i, fetchCtx.Err())
		}
	}
}

func TestDrainOutboxErrorReporting(t *testing.T) {
	t.Run("reports a live-context error", func(t *testing.T) {
		logs := captureDefaultLogs(t)
		fetchErr := errors.New("fetch unavailable")
		db := &relayDBFake{fetchResults: []relayFetchResult{{err: fetchErr}}}
		app := &App{db: db, kafka: newRelayProducerFake()}

		app.drainOutbox(context.Background())

		if db.fetchCalls != 1 {
			t.Fatalf("expected one fetch, got %d", db.fetchCalls)
		}
		for _, want := range []string{"application_error", "handler=outbox_relay", "error_type=relay"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("expected log to contain %q, got %q", want, logs.String())
			}
		}
	})

	t.Run("does not report shutdown cancellation", func(t *testing.T) {
		logs := captureDefaultLogs(t)
		db := &relayDBFake{fetchResults: []relayFetchResult{{err: context.Canceled}}}
		app := &App{db: db, kafka: newRelayProducerFake()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		app.drainOutbox(ctx)

		if db.fetchCalls != 1 {
			t.Fatalf("expected one fetch, got %d", db.fetchCalls)
		}
		if logs.Len() != 0 {
			t.Fatalf("expected no shutdown error log, got %q", logs.String())
		}
	})
}

func TestRelayBatchFetchResults(t *testing.T) {
	t.Run("returns fetch error", func(t *testing.T) {
		fetchErr := errors.New("fetch failed")
		db := &relayDBFake{fetchResults: []relayFetchResult{{err: fetchErr}}}
		producer := newRelayProducerFake()
		app := &App{db: db, kafka: producer}

		full, err := app.relayBatch(context.Background())

		if full {
			t.Fatal("fetch error must not report a full batch")
		}
		if !errors.Is(err, fetchErr) {
			t.Fatalf("expected fetch error, got %v", err)
		}
		if !reflect.DeepEqual(db.fetchLimits, []int{outboxBatchSize}) {
			t.Fatalf("unexpected fetch limits: %v", db.fetchLimits)
		}
		if len(producer.records) != 0 {
			t.Fatalf("expected no produced records, got %d", len(producer.records))
		}
		if len(db.markCalls) != 0 {
			t.Fatalf("expected no mark calls, got %d", len(db.markCalls))
		}
	})

	t.Run("returns drained for empty result", func(t *testing.T) {
		db := &relayDBFake{fetchResults: []relayFetchResult{{}}}
		producer := newRelayProducerFake()
		app := &App{db: db, kafka: producer}

		full, err := app.relayBatch(context.Background())

		if err != nil {
			t.Fatalf("relayBatch returned error: %v", err)
		}
		if full {
			t.Fatal("empty result must not report a full batch")
		}
		if len(producer.records) != 0 {
			t.Fatalf("expected no produced records, got %d", len(producer.records))
		}
		if len(db.markCalls) != 0 {
			t.Fatalf("expected no mark calls, got %d", len(db.markCalls))
		}
	})
}

func TestRelayBatchPublishesInOrderAndMarks(t *testing.T) {
	rows := []models.OutboxRow{
		{
			ID:      11,
			Topic:   "iam.user.created",
			Key:     "user-11",
			Payload: []byte("{\n  \"user_id\": \"user-11\"\n}"),
			Headers: map[string]string{
				"correlation_id": "request-11",
				"trace_id":       "trace-11",
			},
		},
		{
			ID:      12,
			Topic:   "iam.user.updated",
			Key:     "user-12",
			Payload: []byte(`{"user_id":"user-12"}`),
		},
	}
	db := &relayDBFake{fetchResults: []relayFetchResult{{rows: rows}}}
	producer := newRelayProducerFake()
	app := &App{db: db, kafka: producer}
	ctx := context.Background()

	full, err := app.relayBatch(ctx)

	if err != nil {
		t.Fatalf("relayBatch returned error: %v", err)
	}
	if full {
		t.Fatal("underfull result reported a full batch")
	}
	if len(producer.records) != len(rows) {
		t.Fatalf("expected %d records, got %d", len(rows), len(producer.records))
	}
	for i, row := range rows {
		record := producer.records[i]
		if record.ctx != ctx {
			t.Errorf("record %d received a different context", i)
		}
		if record.topic != row.Topic {
			t.Errorf("record %d topic = %q, want %q", i, record.topic, row.Topic)
		}
		if string(record.key) != row.Key {
			t.Errorf("record %d key = %q, want %q", i, record.key, row.Key)
		}
		raw, ok := record.value.(json.RawMessage)
		if !ok {
			t.Fatalf("record %d value type = %T, want json.RawMessage", i, record.value)
		}
		if !bytes.Equal(raw, row.Payload) {
			t.Errorf("record %d payload = %q, want byte-for-byte %q", i, raw, row.Payload)
		}
		if got := recordHeaders(record.headers); !reflect.DeepEqual(got, row.Headers) {
			t.Errorf("record %d headers = %v, want %v", i, got, row.Headers)
		}
	}
	if len(db.markCalls) != 1 {
		t.Fatalf("expected one mark call, got %d", len(db.markCalls))
	}
	assertInt64sEqual(t, db.markCalls[0], []int64{11, 12})
}

func TestRelayBatchReportsFullBatch(t *testing.T) {
	rows := makeOutboxRows(outboxBatchSize, 1)
	db := &relayDBFake{fetchResults: []relayFetchResult{{rows: rows}}}
	producer := newRelayProducerFake()
	app := &App{db: db, kafka: producer}

	full, err := app.relayBatch(context.Background())

	if err != nil {
		t.Fatalf("relayBatch returned error: %v", err)
	}
	if !full {
		t.Fatal("expected a fully delivered batch to report full")
	}
	if len(producer.records) != outboxBatchSize {
		t.Fatalf("expected %d records, got %d", outboxBatchSize, len(producer.records))
	}
	for i, row := range rows {
		if string(producer.records[i].key) != row.Key {
			t.Fatalf("record %d key = %q, want %q", i, producer.records[i].key, row.Key)
		}
	}
	if len(db.markCalls) != 1 {
		t.Fatalf("expected one mark call, got %d", len(db.markCalls))
	}
	assertInt64sEqual(t, db.markCalls[0], outboxIDs(rows))
}

func TestRelayBatchStopsAtFirstProduceError(t *testing.T) {
	produceErr := errors.New("Kafka unavailable")
	rows := makeOutboxRows(3, 21)

	t.Run("first record", func(t *testing.T) {
		db := &relayDBFake{fetchResults: []relayFetchResult{{rows: rows}}}
		producer := newRelayProducerFake()
		producer.failAt = 0
		producer.produceErr = produceErr
		app := &App{db: db, kafka: producer}

		full, err := app.relayBatch(context.Background())

		if full {
			t.Fatal("producer error must not report a full batch")
		}
		if !errors.Is(err, produceErr) {
			t.Fatalf("expected produce error, got %v", err)
		}
		if len(producer.records) != 1 {
			t.Fatalf("expected one attempted record, got %d", len(producer.records))
		}
		if len(db.markCalls) != 0 {
			t.Fatalf("expected no mark calls, got %d", len(db.markCalls))
		}
	})

	t.Run("after a successful record", func(t *testing.T) {
		db := &relayDBFake{fetchResults: []relayFetchResult{{rows: rows}}}
		producer := newRelayProducerFake()
		producer.failAt = 1
		producer.produceErr = produceErr
		app := &App{db: db, kafka: producer}

		full, err := app.relayBatch(context.Background())

		if full {
			t.Fatal("producer error must not report a full batch")
		}
		if !errors.Is(err, produceErr) {
			t.Fatalf("expected produce error, got %v", err)
		}
		if len(producer.records) != 2 {
			t.Fatalf("expected two attempted records, got %d", len(producer.records))
		}
		if string(producer.records[0].key) != rows[0].Key ||
			string(producer.records[1].key) != rows[1].Key {
			t.Fatalf("records attempted out of order: %q, %q", producer.records[0].key, producer.records[1].key)
		}
		if len(db.markCalls) != 1 {
			t.Fatalf("expected one mark call, got %d", len(db.markCalls))
		}
		assertInt64sEqual(t, db.markCalls[0], []int64{rows[0].ID})
	})
}

func TestRelayBatchReturnsMarkError(t *testing.T) {
	markErr := errors.New("mark failed")
	rows := makeOutboxRows(2, 31)
	db := &relayDBFake{
		fetchResults: []relayFetchResult{{rows: rows}},
		markErr:      markErr,
	}
	producer := newRelayProducerFake()
	app := &App{db: db, kafka: producer}

	full, err := app.relayBatch(context.Background())

	if full {
		t.Fatal("mark error must not report a full batch")
	}
	if !errors.Is(err, markErr) {
		t.Fatalf("expected mark error, got %v", err)
	}
	if len(producer.records) != len(rows) {
		t.Fatalf("expected %d produced records, got %d", len(rows), len(producer.records))
	}
	if len(db.markCalls) != 1 {
		t.Fatalf("expected one mark call, got %d", len(db.markCalls))
	}
	assertInt64sEqual(t, db.markCalls[0], outboxIDs(rows))
}

func captureDefaultLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
	return &logs
}

func makeOutboxRows(count int, firstID int64) []models.OutboxRow {
	rows := make([]models.OutboxRow, count)
	for i := range rows {
		id := firstID + int64(i)
		rows[i] = models.OutboxRow{
			ID:      id,
			Topic:   "iam.user.updated",
			Key:     fmt.Sprintf("user-%d", id),
			Payload: []byte(fmt.Sprintf(`{"user_id":"user-%d"}`, id)),
			Headers: map[string]string{"correlation_id": fmt.Sprintf("request-%d", id)},
		}
	}
	return rows
}

func outboxIDs(rows []models.OutboxRow) []int64 {
	ids := make([]int64, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func recordHeaders(headers []kafka.RecordHeader) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for _, header := range headers {
		result[header.Key] = string(header.Value)
	}
	return result
}

func assertInt64sEqual(t *testing.T, got, want []int64) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}
}
