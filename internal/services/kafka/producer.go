package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	kafkago "github.com/segmentio/kafka-go"
)

type Producer interface {
	Publish(ctx context.Context, topic, key string, value any) error
	Close() error
}

type kafkaProducer struct {
	brokers []string
}

func NewProducer() Producer {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = "localhost:9092"
	}
	return &kafkaProducer{brokers: []string{brokers}}
}

func (p *kafkaProducer) Publish(ctx context.Context, topic, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("kafka marshal: %w", err)
	}

	w := &kafkago.Writer{
		Addr:  kafkago.TCP(p.brokers...),
		Topic: topic,
	}
	defer w.Close()

	return w.WriteMessages(ctx, kafkago.Message{
		Key:   []byte(key),
		Value: payload,
	})
}

func (p *kafkaProducer) Close() error { return nil }
