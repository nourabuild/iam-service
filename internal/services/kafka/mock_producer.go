package kafka

import "context"

type MockProducer struct{}

func NewMockProducer() KafkaRepository {
	return &MockProducer{}
}

func (m *MockProducer) Produce(_ context.Context, _ string, _ []byte, _ any) error {
	return nil
}

func (m *MockProducer) Close() {}
