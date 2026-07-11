package kafka

import (
	"context"
	"testing"
)

func TestSplitTrim(t *testing.T) {
	got := splitTrim(" broker-a:9092,\tbroker-b:9092\n broker-c:9092 ")
	want := []string{"broker-a:9092", "broker-b:9092", "broker-c:9092"}
	if len(got) != len(want) {
		t.Fatalf("splitTrim returned %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitTrim[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestProduceRejectsInvalidRecordBeforeUsingClient(t *testing.T) {
	service := &KafkaService{}
	if err := service.Produce(context.Background(), "", nil, "value"); err == nil {
		t.Fatal("empty topic was accepted")
	}
	if err := service.Produce(context.Background(), "topic", nil, make(chan int)); err == nil {
		t.Fatal("unmarshalable record was accepted")
	}
}
