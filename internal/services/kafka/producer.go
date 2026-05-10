package kafka

import (
	"context"
	"encoding/json"
	"os"

	"github.com/twmb/franz-go/pkg/kgo"
)

type KafkaRepository interface {
	Produce(ctx context.Context, topic string, key []byte, value any) error
	Close()
}

type KafkaService struct {
	client *kgo.Client
}

func NewKafkaService() *KafkaService {
	brokers := parse(os.Getenv("KAFKA_BROKERS"))

	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(3),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		client.Close()
		panic(err)
	}

	return &KafkaService{
		client: client,
	}
}

func (p *KafkaService) Produce(ctx context.Context, topic string, key []byte, value any) error {
	if topic == "" {
		return nil
	}

	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return p.client.ProduceSync(ctx, &kgo.Record{Topic: topic, Key: key, Value: payload}).FirstErr()
}

func (p *KafkaService) Close() {
	p.client.Close()
}
