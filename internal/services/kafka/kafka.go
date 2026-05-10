package kafka

import (
	"strings"
	"time"
)

const (
	TopicUserCreated = "iam.user.created"
	TopicUserUpdated = "iam.user.updated"

	defaultBrokers = "localhost:9092"
	defaultTimeout = 10 * time.Second
)

func parse(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = defaultBrokers
	}

	parts := strings.Split(raw, ",")
	brokers := make([]string, 0, len(parts))

	for _, part := range parts {
		broker := strings.TrimSpace(part)
		if broker != "" {
			brokers = append(brokers, broker)
		}
	}

	if len(brokers) == 0 {
		return []string{defaultBrokers}
	}

	return brokers
}
