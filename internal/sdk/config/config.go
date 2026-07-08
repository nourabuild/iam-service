package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	minJWTSecretLength = 32

	defaultEnv              = "development"
	defaultHTTPPort         = "10067"
	defaultDBSchema         = "public"
	defaultDBSSLMode        = "disable"
	defaultJWTIssuer        = "noura-iam-service"
	defaultAccessTokenTTL   = 15 * time.Minute
	defaultRefreshTokenTTL  = 30 * 24 * time.Hour
	defaultKafkaBrokers     = "localhost:9092"
	defaultKafkaPartitions  = 3
	defaultKafkaReplicas    = 1
	defaultSentryFlush      = 2 * time.Second
	defaultMailtrapSendURL  = "https://send.api.mailtrap.io/api/send"
	defaultMailtrapFrom     = "noreply@example.com"
	defaultMailtrapFromName = "IAM Service"
	defaultResetURL         = "https://meets.noura.software/reset-password"
)

type Config struct {
	Env           string
	HTTP          HTTP
	DB            DB
	Auth          AuthConfig
	CORS          CORS
	Kafka         Kafka
	Mailtrap      Mailtrap
	Sentry        Sentry
	Observability Observability
}

type HTTP struct {
	Port         string
	IdleTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type DB struct {
	Host     string
	Port     string
	Username string
	Password string
	Database string
	Schema   string
	SSLMode  string
}

type AuthConfig struct {
	JWTSecret       string
	RefreshSecret   string
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type CORS struct {
	AllowOrigins     []string
	AllowCredentials bool
}

type Kafka struct {
	Brokers         []string
	TopicPartitions int
	TopicReplicas   int
}

type Mailtrap struct {
	APIToken         string
	APIURL           string
	TemplateUUID     string
	SenderEmail      string
	SenderName       string
	PasswordResetURL string
}

type Sentry struct {
	DSN                    string
	Environment            string
	Release                string
	SentryTracesSampleRate float64
	SentryFlushTimeout     time.Duration
}

type Observability struct {
	ServiceName      string
	OTLPHTTPEndpoint string
}

func Load() (Config, error) {
	cfg := Config{
		Env: envOr("APP_ENV", defaultEnv),
		HTTP: HTTP{
			Port:         firstNonEmpty(env("HTTP_PORT"), env("PORT"), defaultHTTPPort),
			IdleTimeout:  time.Minute,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
		DB: LoadDB(),
		Auth: AuthConfig{
			JWTSecret:       env("JWT_ACCESS_TOKEN_SECRET"),
			RefreshSecret:   env("JWT_REFRESH_TOKEN_SECRET"),
			Issuer:          envOr("JWT_ISSUER", defaultJWTIssuer),
			AccessTokenTTL:  parseDuration(env("JWT_ACCESS_TOKEN_TTL"), defaultAccessTokenTTL),
			RefreshTokenTTL: parseDuration(env("JWT_REFRESH_TOKEN_TTL"), defaultRefreshTokenTTL),
		},
		CORS: CORS{
			AllowOrigins:     splitList(env("CORS_ALLOW_ORIGINS")),
			AllowCredentials: parseBool(env("CORS_ALLOW_CREDENTIALS"), false),
		},
		Kafka: Kafka{
			Brokers:         splitList(envOr("KAFKA_BROKERS", defaultKafkaBrokers)),
			TopicPartitions: parseInt(env("KAFKA_TOPIC_PARTITIONS"), defaultKafkaPartitions),
			TopicReplicas:   parseInt(env("KAFKA_TOPIC_REPLICAS"), defaultKafkaReplicas),
		},
		Mailtrap: Mailtrap{
			APIToken:         env("MAILTRAP_API_TOKEN"),
			APIURL:           envOr("MAILTRAP_API_URL", defaultMailtrapSendURL),
			TemplateUUID:     env("MAILTRAP_TEMPLATE_UUID"),
			SenderEmail:      envOr("MAILTRAP_SENDER_EMAIL", defaultMailtrapFrom),
			SenderName:       envOr("MAILTRAP_SENDER_NAME", defaultMailtrapFromName),
			PasswordResetURL: envOr("PASSWORD_RESET_URL", defaultResetURL),
		},
		Sentry: Sentry{
			DSN:                    env("SENTRY_DSN"),
			Environment:            envOr("SENTRY_ENVIRONMENT", defaultEnv),
			Release:                env("SENTRY_RELEASE"),
			SentryTracesSampleRate: parseFloat(firstNonEmpty(env("SENTRY_TRACES_SAMPLE_RATE"), env("SENTRY_SAMPLE_RATE")), 1),
			SentryFlushTimeout:     parseDuration(env("SENTRY_FLUSH_TIMEOUT"), defaultSentryFlush),
		},
		Observability: Observability{
			ServiceName:      envOr("OBSERVABILITY_SERVICE_NAME", "iam-service-api"),
			OTLPHTTPEndpoint: envOr("OTLP_HTTP_ENDPOINT", ""),
		},
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func LoadDB() DB {
	return DB{
		Host:     env("BLUEPRINT_DB_HOST"),
		Port:     env("BLUEPRINT_DB_PORT"),
		Username: env("BLUEPRINT_DB_USERNAME"),
		Password: env("BLUEPRINT_DB_PASSWORD"),
		Database: env("BLUEPRINT_DB_DATABASE"),
		Schema:   envOr("BLUEPRINT_DB_SCHEMA", defaultDBSchema),
		SSLMode:  envOr("BLUEPRINT_DB_SSLMODE", defaultDBSSLMode),
	}
}

func (c Config) validate() error {
	var problems []error

	for key, value := range map[string]string{
		"BLUEPRINT_DB_HOST":     c.DB.Host,
		"BLUEPRINT_DB_PORT":     c.DB.Port,
		"BLUEPRINT_DB_USERNAME": c.DB.Username,
		"BLUEPRINT_DB_PASSWORD": c.DB.Password,
		"BLUEPRINT_DB_DATABASE": c.DB.Database,
	} {
		if value == "" {
			problems = append(problems, fmt.Errorf("%s is required", key))
		}
	}

	if len(c.Auth.JWTSecret) < minJWTSecretLength {
		problems = append(problems, fmt.Errorf("JWT_ACCESS_TOKEN_SECRET must be at least %d characters", minJWTSecretLength))
	}
	if len(c.Auth.RefreshSecret) < minJWTSecretLength {
		problems = append(problems, fmt.Errorf("JWT_REFRESH_TOKEN_SECRET must be at least %d characters", minJWTSecretLength))
	}
	if c.Auth.Issuer == "" {
		problems = append(problems, fmt.Errorf("JWT_ISSUER is required"))
	}

	if len(problems) > 0 {
		return fmt.Errorf("configuration problems: %v", problems)
	}

	return nil
}

func env(key string) string {
	return normalize(os.Getenv(key))
}

func envOr(key, fallback string) string {
	if value := env(key); value != "" {
		return value
	}
	return fallback
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value
	}

	first := value[0]
	last := value[len(value)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return value[1 : len(value)-1]
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func splitList(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func parseDuration(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseBool(raw string, fallback bool) bool {
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseFloat(raw string, fallback float64) float64 {
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return value
}

func parseInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
