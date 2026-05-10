package kafka

import (
	"context"
	"errors"
)

type mockProducer struct{}

func NewMockProducer() Producer {
	return &mockProducer{}
}

func (m *mockProducer) Publish(ctx context.Context, topic, key string, value any) error {
	if key == "kafka_publish_error" {
		return errors.New("error publishing kafka message")
	}
	return nil
}

func (m *mockProducer) Close() error { return nil }
