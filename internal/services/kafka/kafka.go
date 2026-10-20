// Package kafka publishes IAM lifecycle events.
package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

// Producer synchronously publishes lifecycle events to Kafka.
type Producer struct {
	client *kgo.Client
}

// New connects a Producer and ensures the IAM lifecycle topics exist.
func New(ctx context.Context, cfg config.Kafka) (*Producer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka brokers are required")
	}
	if cfg.Partitions <= 0 {
		return nil, errors.New("kafka topic partitions must be positive")
	}
	if cfg.Replicas <= 0 {
		return nil, errors.New("kafka topic replicas must be positive")
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(3),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create kafka client: %w", err)
	}

	startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := client.Ping(startupCtx); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping kafka brokers: %w", err)
	}

	adm := kadm.NewClient(client)
	topics := []string{models.TopicUserCreated, models.TopicUserUpdated}

	resp, err := adm.CreateTopics(startupCtx, cfg.Partitions, cfg.Replicas, nil, topics...)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("create kafka topics: %w", err)
	}

	for _, r := range resp {
		existed := errors.Is(r.Err, kerr.TopicAlreadyExists)
		if r.Err != nil && !existed {
			client.Close()
			return nil, fmt.Errorf("ensure kafka topic %q: %w", r.Topic, r.Err)
		}
	}

	return &Producer{client: client}, nil
}

// Produce JSON-encodes value and waits for Kafka to acknowledge the record.
func (p *Producer) Produce(ctx context.Context, topic string, key []byte, value any, headers map[string]string) error {
	if topic == "" {
		return errors.New("kafka topic is required")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal kafka record for topic %q: %w", topic, err)
	}

	recordHeaders := make([]kgo.RecordHeader, 0, len(headers))
	for header, value := range headers {
		recordHeaders = append(recordHeaders, kgo.RecordHeader{Key: header, Value: []byte(value)})
	}

	err = p.client.ProduceSync(ctx, &kgo.Record{
		Topic:   topic,
		Key:     key,
		Value:   data,
		Headers: recordHeaders,
	}).FirstErr()
	if err != nil {
		return fmt.Errorf("produce kafka record to topic %q: %w", topic, err)
	}

	return nil
}

// Close flushes pending records and closes the underlying client.
func (p *Producer) Close() {
	p.client.Close()
}
