package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
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

func NewKafkaService() KafkaRepository {
	brokers := splitTrim(getenv("KAFKA_BROKERS", "localhost:9092"))
	partitions := int32(getenvInt("KAFKA_TOPIC_PARTITIONS", 3))
	replicas := int16(getenvInt("KAFKA_TOPIC_REPLICAS", 1))

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordRetries(3),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		log.Printf("kafka unavailable: %v", err)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		client.Close()
		log.Printf("kafka ping failed: %v", err)
		return nil
	}

	adm := kadm.NewClient(client)
	topics := []string{ProduceTopicUserCreated, ProduceTopicUserUpdated}

	resp, err := adm.CreateTopics(ctx, partitions, replicas, nil, topics...)
	if err != nil {
		client.Close()
		log.Printf("kafka create topics failed: %v", err)
		return nil
	}

	for _, r := range resp {
		existed := errors.Is(r.Err, kerr.TopicAlreadyExists)
		if r.Err != nil && !existed {
			client.Close()
			log.Printf("kafka topic ensure failed topic=%s: %v", r.Topic, r.Err)
			return nil
		}
		log.Printf(
			"kafka topic ensured topic=%s already_existed=%v", r.Topic, existed)
	}

	return &KafkaService{client: client}
}

func (s *KafkaService) Produce(ctx context.Context, topic string, key []byte, value any) error {
	if topic == "" {
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		log.Printf("kafka producer marshal failed topic=%s: %v", topic, err)
		return err
	}

	start := time.Now()
	err = s.client.ProduceSync(ctx, &kgo.Record{
		Topic: topic,
		Key:   key,
		Value: data,
	}).FirstErr()
	if err != nil {
		log.Printf("kafka producer send failed topic=%s key=%s bytes=%d elapsed=%s: %v",
			topic, key, len(data), time.Since(start), err)
		return err
	}

	log.Printf("kafka producer sent topic=%s key=%s bytes=%d elapsed=%s",
		topic, key, len(data), time.Since(start))
	return nil
}

func (s *KafkaService) Close() {
	s.client.Close()
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
