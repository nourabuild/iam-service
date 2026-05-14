package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	ProduceTopicUserCreated = "iam.user.created"
	ProduceTopicUserUpdated = "iam.user.updated"

	defaultPartitions int32 = 3
	defaultReplicas   int16 = 1
)

type KafkaRepository interface {
	Produce(ctx context.Context, topic string, key []byte, value any) error
	Close()
}

type KafkaService struct {
	client *kgo.Client
}

// no consumer, no handle
func NewKafkaService() KafkaRepository {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = "localhost:9092"
	}

	client, err := kgo.NewClient(
		kgo.SeedBrokers(strings.Split(brokers, ",")...),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(3),
	)
	if err != nil {
		panic("failed to create kafka client: " + err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// --- Inlined ensureTopics logic ---
	adm := kadm.NewClient(client)
	topics := []string{ProduceTopicUserCreated, ProduceTopicUserUpdated}

	resp, err := adm.CreateTopics(ctx, defaultPartitions, defaultReplicas, nil, topics...)
	if err != nil {
		client.Close()
		panic("failed to ensure kafka topics: " + err.Error())
	}

	for _, r := range resp {
		existed := errors.Is(r.Err, kerr.TopicAlreadyExists)
		if r.Err != nil && !existed {
			client.Close()
			panic("failed to ensure kafka topic " + r.Topic + ": " + r.Err.Error())
		}
		slog.Info("kafka topic ensured", "topic", r.Topic, "already_existed", existed)
	}
	// ----------------------------------

	return &KafkaService{client: client}
}

func (s *KafkaService) Produce(ctx context.Context, topic string, key []byte, value any) error {
	if topic == "" {
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		slog.Info("kafka producer marshal failed", "topic", topic, "error", err)
		return err
	}

	start := time.Now()
	err = s.client.ProduceSync(ctx, &kgo.Record{
		Topic: topic,
		Key:   key,
		Value: data,
	}).FirstErr()
	if err != nil {
		slog.Info("kafka producer send failed", "topic", topic, "key", string(key), "bytes", len(data), "elapsed", time.Since(start), "error", err)
		return err
	}

	slog.Info("kafka producer sent data", "topic", topic, "key", string(key), "bytes", len(data), "elapsed", time.Since(start))
	return nil
}

func (s *KafkaService) Close() {
	s.client.Close()
}
