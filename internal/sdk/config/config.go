// Package config loads and validates application configuration.
package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/mail"
	"net/url"
	"os"
	"slices"
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
	Mailtrap      Mailtrap
	Sentry        Sentry
	Observability Observability
}

type HTTP struct {
	Port           string
	IdleTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	TrustedProxies []string
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
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type CORS struct {
	AllowOrigins     []string
	AllowCredentials bool
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
	var problems []error
	accessTokenTTL, err := parseDuration(env("JWT_ACCESS_TOKEN_TTL"), defaultAccessTokenTTL)
	if err != nil {
		problems = append(problems, fmt.Errorf("JWT_ACCESS_TOKEN_TTL: %w", err))
	}
	refreshTokenTTL, err := parseDuration(env("JWT_REFRESH_TOKEN_TTL"), defaultRefreshTokenTTL)
	if err != nil {
		problems = append(problems, fmt.Errorf("JWT_REFRESH_TOKEN_TTL: %w", err))
	}
	allowCredentials, err := parseBool(env("CORS_ALLOW_CREDENTIALS"), false)
	if err != nil {
		problems = append(problems, fmt.Errorf("CORS_ALLOW_CREDENTIALS: %w", err))
	}
	tracesSampleRate, err := parseFloat(firstNonEmpty(env("SENTRY_TRACES_SAMPLE_RATE"), env("SENTRY_SAMPLE_RATE")), 1)
	if err != nil {
		problems = append(problems, fmt.Errorf("SENTRY_TRACES_SAMPLE_RATE: %w", err))
	}
	sentryFlushTimeout, err := parseDuration(env("SENTRY_FLUSH_TIMEOUT"), defaultSentryFlush)
	if err != nil {
		problems = append(problems, fmt.Errorf("SENTRY_FLUSH_TIMEOUT: %w", err))
	}

	cfg := Config{
		Env: envOr("APP_ENV", defaultEnv),
		HTTP: HTTP{
			Port:           firstNonEmpty(env("HTTP_PORT"), env("PORT"), defaultHTTPPort),
			IdleTimeout:    time.Minute,
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   10 * time.Second,
			TrustedProxies: splitList(env("TRUSTED_PROXIES")),
		},
		DB: LoadDB(),
		Auth: AuthConfig{
			JWTSecret:       env("JWT_ACCESS_TOKEN_SECRET"),
			Issuer:          envOr("JWT_ISSUER", defaultJWTIssuer),
			AccessTokenTTL:  accessTokenTTL,
			RefreshTokenTTL: refreshTokenTTL,
		},
		CORS: CORS{
			AllowOrigins:     splitList(env("CORS_ALLOW_ORIGINS")),
			AllowCredentials: allowCredentials,
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
			SentryTracesSampleRate: tracesSampleRate,
			SentryFlushTimeout:     sentryFlushTimeout,
		},
		Observability: Observability{
			ServiceName:      envOr("OBSERVABILITY_SERVICE_NAME", "iam-service-api"),
			OTLPHTTPEndpoint: envOr("OTLP_HTTP_ENDPOINT", ""),
		},
	}

	if err := cfg.validate(); err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return Config{}, fmt.Errorf("configuration problems: %w", errors.Join(problems...))
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

	required := []struct {
		key   string
		value string
	}{
		{key: "BLUEPRINT_DB_HOST", value: c.DB.Host},
		{key: "BLUEPRINT_DB_PORT", value: c.DB.Port},
		{key: "BLUEPRINT_DB_USERNAME", value: c.DB.Username},
		{key: "BLUEPRINT_DB_PASSWORD", value: c.DB.Password},
		{key: "BLUEPRINT_DB_DATABASE", value: c.DB.Database},
	}
	for _, item := range required {
		if item.value == "" {
			problems = append(problems, fmt.Errorf("%s is required", item.key))
		}
	}

	if len(c.Auth.JWTSecret) < minJWTSecretLength {
		problems = append(problems, fmt.Errorf("JWT_ACCESS_TOKEN_SECRET must be at least %d characters", minJWTSecretLength))
	}
	if c.Auth.Issuer == "" {
		problems = append(problems, fmt.Errorf("JWT_ISSUER is required"))
	}
	if !validPort(c.HTTP.Port) {
		problems = append(problems, fmt.Errorf("HTTP_PORT must be an integer between 1 and 65535"))
	}
	if c.DB.Port != "" && !validPort(c.DB.Port) {
		problems = append(problems, fmt.Errorf("BLUEPRINT_DB_PORT must be an integer between 1 and 65535"))
	}
	if c.Auth.AccessTokenTTL <= 0 {
		problems = append(problems, fmt.Errorf("JWT_ACCESS_TOKEN_TTL must be positive"))
	}
	if c.Auth.RefreshTokenTTL <= 0 {
		problems = append(problems, fmt.Errorf("JWT_REFRESH_TOKEN_TTL must be positive"))
	}
	if math.IsNaN(c.Sentry.SentryTracesSampleRate) || c.Sentry.SentryTracesSampleRate < 0 || c.Sentry.SentryTracesSampleRate > 1 {
		problems = append(problems, fmt.Errorf("SENTRY_TRACES_SAMPLE_RATE must be between 0 and 1"))
	}
	if c.Sentry.SentryFlushTimeout <= 0 {
		problems = append(problems, fmt.Errorf("SENTRY_FLUSH_TIMEOUT must be positive"))
	}
	for _, proxy := range c.HTTP.TrustedProxies {
		if net.ParseIP(proxy) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			problems = append(problems, fmt.Errorf("TRUSTED_PROXIES contains invalid IP or CIDR %q", proxy))
		}
	}
	for _, origin := range c.CORS.AllowOrigins {
		if origin == "*" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			problems = append(problems, fmt.Errorf("CORS_ALLOW_ORIGINS contains invalid origin %q", origin))
		}
	}
	if c.CORS.AllowCredentials && (len(c.CORS.AllowOrigins) == 0 || slices.Contains(c.CORS.AllowOrigins, "*")) {
		problems = append(problems, fmt.Errorf("CORS_ALLOW_CREDENTIALS requires explicit CORS_ALLOW_ORIGINS"))
	}
	if address, err := mail.ParseAddress(c.Mailtrap.SenderEmail); err != nil || address.Address != c.Mailtrap.SenderEmail {
		problems = append(problems, fmt.Errorf("MAILTRAP_SENDER_EMAIL must be a bare email address"))
	}
	if c.Mailtrap.APIToken != "" && c.Mailtrap.TemplateUUID == "" {
		problems = append(problems, fmt.Errorf("MAILTRAP_TEMPLATE_UUID is required when MAILTRAP_API_TOKEN is set"))
	}
	configuredURLs := []struct {
		key string
		url string
	}{
		{key: "MAILTRAP_API_URL", url: c.Mailtrap.APIURL},
		{key: "PASSWORD_RESET_URL", url: c.Mailtrap.PasswordResetURL},
	}
	for _, item := range configuredURLs {
		parsed, err := url.Parse(item.url)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			problems = append(problems, fmt.Errorf("%s must be an absolute HTTP(S) URL", item.key))
		}
	}

	if len(problems) > 0 {
		return errors.Join(problems...)
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

func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback, fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	return value, nil
}

func parseBool(raw string, fallback bool) (bool, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, fmt.Errorf("invalid boolean %q: %w", raw, err)
	}
	return value, nil
}

func parseFloat(raw string, fallback float64) (float64, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback, fmt.Errorf("invalid number %q: %w", raw, err)
	}
	return value, nil
}

func validPort(raw string) bool {
	port, err := strconv.Atoi(raw)
	return err == nil && port >= 1 && port <= 65535
}
