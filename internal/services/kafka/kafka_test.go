package kafka

import (
	"testing"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Kafka
	}{
		{name: "missing brokers"},
		{name: "missing partitions", cfg: config.Kafka{Brokers: []string{"broker:9092"}, Replicas: 1}},
		{name: "missing replicas", cfg: config.Kafka{Brokers: []string{"broker:9092"}, Partitions: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(t.Context(), tt.cfg); err == nil {
				t.Fatalf("New accepted invalid config: %+v", tt.cfg)
			}
		})
	}
}

func TestProduceRejectsInvalidRecordBeforeUsingClient(t *testing.T) {
	producer := &Producer{}
	if err := producer.Produce(t.Context(), "", nil, "value", nil); err == nil {
		t.Fatal("empty topic was accepted")
	}
	if err := producer.Produce(t.Context(), "topic", nil, make(chan int), nil); err == nil {
		t.Fatal("unmarshalable record was accepted")
	}
}
