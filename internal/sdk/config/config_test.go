package config

import (
	"strings"
	"testing"
)

func setValidEnvironment(t *testing.T) {
	t.Helper()

	values := map[string]string{
		"APP_ENV":                    "",
		"HTTP_PORT":                  "",
		"PORT":                       "",
		"TRUSTED_PROXIES":            "",
		"BLUEPRINT_DB_HOST":          "localhost",
		"BLUEPRINT_DB_PORT":          "5432",
		"BLUEPRINT_DB_USERNAME":      "postgres",
		"BLUEPRINT_DB_PASSWORD":      "postgres",
		"BLUEPRINT_DB_DATABASE":      "iam",
		"BLUEPRINT_DB_SCHEMA":        "",
		"BLUEPRINT_DB_SSLMODE":       "",
		"JWT_ACCESS_TOKEN_SECRET":    "test-access-secret-0123456789abcdef",
		"JWT_ISSUER":                 "",
		"JWT_ACCESS_TOKEN_TTL":       "",
		"JWT_REFRESH_TOKEN_TTL":      "",
		"CORS_ALLOW_ORIGINS":         "",
		"CORS_ALLOW_CREDENTIALS":     "",
		"MAILTRAP_API_TOKEN":         "",
		"MAILTRAP_API_URL":           "",
		"MAILTRAP_TEMPLATE_UUID":     "",
		"MAILTRAP_SENDER_EMAIL":      "",
		"MAILTRAP_SENDER_NAME":       "",
		"PASSWORD_RESET_URL":         "",
		"SENTRY_TRACES_SAMPLE_RATE":  "",
		"SENTRY_SAMPLE_RATE":         "",
		"SENTRY_FLUSH_TIMEOUT":       "",
		"OBSERVABILITY_SERVICE_NAME": "",
		"OTLP_HTTP_ENDPOINT":         "",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func TestLoadUsesNormalizedTypedConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("BLUEPRINT_DB_PASSWORD", `'p@ss:word'`)
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.10")
	t.Setenv("CORS_ALLOW_ORIGINS", "https://app.example.com, https://admin.example.com")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DB.Password != "p@ss:word" {
		t.Fatalf("DB password = %q, want normalized value", cfg.DB.Password)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 || cfg.HTTP.TrustedProxies[0] != "10.0.0.0/8" {
		t.Fatalf("trusted proxies = %v", cfg.HTTP.TrustedProxies)
	}
	if len(cfg.CORS.AllowOrigins) != 2 || !cfg.CORS.AllowCredentials {
		t.Fatalf("CORS config = %+v", cfg.CORS)
	}
}

func TestLoadRejectsUnsafeRanges(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{name: "HTTP port", key: "HTTP_PORT", value: "70000", wantErr: "HTTP_PORT"},
		{name: "database port", key: "BLUEPRINT_DB_PORT", value: "zero", wantErr: "BLUEPRINT_DB_PORT"},
		{name: "access TTL", key: "JWT_ACCESS_TOKEN_TTL", value: "-1m", wantErr: "JWT_ACCESS_TOKEN_TTL"},
		{name: "trace sample rate", key: "SENTRY_TRACES_SAMPLE_RATE", value: "1.5", wantErr: "SENTRY_TRACES_SAMPLE_RATE"},
		{name: "NaN trace sample rate", key: "SENTRY_TRACES_SAMPLE_RATE", value: "NaN", wantErr: "SENTRY_TRACES_SAMPLE_RATE"},
		{name: "malformed boolean", key: "CORS_ALLOW_CREDENTIALS", value: "sometimes", wantErr: "CORS_ALLOW_CREDENTIALS"},
		{name: "reset URL", key: "PASSWORD_RESET_URL", value: "/reset", wantErr: "PASSWORD_RESET_URL"},
		{name: "trusted proxy", key: "TRUSTED_PROXIES", value: "0.0.0.0/0,not-an-ip", wantErr: "TRUSTED_PROXIES"},
		{name: "CORS origin", key: "CORS_ALLOW_ORIGINS", value: "app.example.com", wantErr: "CORS_ALLOW_ORIGINS"},
		{name: "sender email", key: "MAILTRAP_SENDER_EMAIL", value: "Noura <noreply@example.com>", wantErr: "MAILTRAP_SENDER_EMAIL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(tt.key, tt.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsCredentialsWithWildcardCORS(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("CORS_ALLOW_ORIGINS", "*")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "CORS_ALLOW_CREDENTIALS") {
		t.Fatalf("Load error = %v, want credentialed wildcard CORS rejection", err)
	}
}

func TestLoadRequiresTemplateWhenMailtrapIsEnabled(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("MAILTRAP_API_TOKEN", "token")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MAILTRAP_TEMPLATE_UUID") {
		t.Fatalf("Load error = %v, want missing template rejection", err)
	}
}
