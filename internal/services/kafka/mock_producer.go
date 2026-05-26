package kafka

import (
	"context"

	"github.com/twmb/franz-go/pkg/kgo"
)

type MockProducer struct{}

func NewMockProducer() KafkaRepository {
	return &MockProducer{}
}

func (m *MockProducer) Produce(_ context.Context, _ string, _ []byte, _ any, _ ...kgo.RecordHeader) error {
	return nil
}

func (m *MockProducer) Close() {}
