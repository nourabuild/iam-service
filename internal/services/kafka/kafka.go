package kafka

import (
	"context"
	"encoding/json"
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

type noopKafka struct{}

func (noopKafka) Produce(_ context.Context, _ string, _ []byte, _ any) error { return nil }
func (noopKafka) Close()                                                     {}

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
		return noopKafka{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		client.Close()
		return noopKafka{}
	}

	return &KafkaService{client: client}
}

func (s *KafkaService) Produce(ctx context.Context, topic string, key []byte, value any) error {
	if topic == "" {
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return s.client.ProduceSync(ctx, &kgo.Record{
		Topic: topic,
		Key:   key,
		Value: data,
	}).FirstErr()
}

func (s *KafkaService) Close() {
	s.client.Close()
}
