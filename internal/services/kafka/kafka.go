// Package kafka publishes IAM lifecycle events.
package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	ProduceTopicUserCreated = "iam.user.created"
	ProduceTopicUserUpdated = "iam.user.updated"
	HeaderCorrelationID     = "correlation_id"
)

type KafkaRepository interface {
	Produce(ctx context.Context, topic string, key []byte, value any, headers ...kgo.RecordHeader) error
	Close()
}

type RecordHeader = kgo.RecordHeader

type KafkaService struct {
	client *kgo.Client
}

func NewKafkaService(ctx context.Context) KafkaRepository {
	brokers := splitTrim(os.Getenv("KAFKA_BROKERS"))
	if len(brokers) == 0 {
		slog.InfoContext(ctx, "kafka disabled", "reason", "KAFKA_BROKERS is not configured")
		return nil
	}

	partitionsValue, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("KAFKA_TOPIC_PARTITIONS")), 10, 32)
	if err != nil || partitionsValue <= 0 {
		slog.WarnContext(ctx, "kafka disabled", "reason", "KAFKA_TOPIC_PARTITIONS must be a positive integer")
		return nil
	}
	partitions := int32(partitionsValue)

	replicasValue, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("KAFKA_TOPIC_REPLICAS")), 10, 16)
	if err != nil || replicasValue <= 0 {
		slog.WarnContext(ctx, "kafka disabled", "reason", "KAFKA_TOPIC_REPLICAS must be a positive integer")
		return nil
	}
	replicas := int16(replicasValue)

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(3),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		slog.WarnContext(ctx, "kafka unavailable", "error", err)
		return nil
	}

	startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := client.Ping(startupCtx); err != nil {
		client.Close()
		slog.WarnContext(ctx, "kafka ping failed", "error", err)
		return nil
	}

	adm := kadm.NewClient(client)
	topics := []string{ProduceTopicUserCreated, ProduceTopicUserUpdated}

	resp, err := adm.CreateTopics(startupCtx, partitions, replicas, nil, topics...)
	if err != nil {
		client.Close()
		slog.WarnContext(ctx, "kafka create topics failed", "error", err)
		return nil
	}

	for _, r := range resp {
		existed := errors.Is(r.Err, kerr.TopicAlreadyExists)
		if r.Err != nil && !existed {
			client.Close()
			slog.WarnContext(ctx, "kafka topic ensure failed", "topic", r.Topic, "error", r.Err)
			return nil
		}
		slog.InfoContext(ctx, "kafka topic ensured", "topic", r.Topic, "already_existed", existed)
	}

	return &KafkaService{client: client}
}

func (s *KafkaService) Produce(ctx context.Context, topic string, key []byte, value any, headers ...kgo.RecordHeader) error {
	if topic == "" {
		return errors.New("kafka topic is required")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal kafka record for topic %q: %w", topic, err)
	}

	start := time.Now()
	err = s.client.ProduceSync(ctx, &kgo.Record{
		Topic:   topic,
		Key:     key,
		Value:   data,
		Headers: headers,
	}).FirstErr()
	if err != nil {
		slog.ErrorContext(ctx, "kafka producer send failed",
			"topic", topic, "key", string(key), "bytes", len(data), "elapsed", time.Since(start), "error", err)
		return fmt.Errorf("produce kafka record to topic %q: %w", topic, err)
	}

	slog.DebugContext(ctx, "kafka producer sent",
		"topic", topic, "key", string(key), "bytes", len(data), "elapsed", time.Since(start))
	return nil
}

func (s *KafkaService) Close() {
	s.client.Close()
}

func splitTrim(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}
