package kafka

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	ProduceTopicUserCreated = "iam.user.created"
	ProduceTopicUserUpdated = "iam.user.updated"
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

	// ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// defer cancel()

	// if err := client.Ping(ctx); err != nil {
	// 	client.Close()
	// 	panic("kafka ping failed: " + err.Error())
	// }

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
