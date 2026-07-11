// Package mailtrap sends transactional email through the Mailtrap API.
package mailtrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

type MailtrapRepository interface {
	SendPasswordResetEmail(ctx context.Context, to, token string) error
}

type MailtrapService struct {
	apiToken         string
	apiURL           string
	fromEmail        string
	fromName         string
	templateUUID     string
	passwordResetURL string
	httpClient       *http.Client
}

func NewMailtrapService(cfg config.Mailtrap) *MailtrapService {
	return &MailtrapService{
		apiToken:         cfg.APIToken,
		apiURL:           cfg.APIURL,
		fromEmail:        cfg.SenderEmail,
		fromName:         cfg.SenderName,
		templateUUID:     cfg.TemplateUUID,
		passwordResetURL: cfg.PasswordResetURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (m *MailtrapService) SendPasswordResetEmail(ctx context.Context, to, token string) error {
	to = strings.TrimSpace(to)
	token = strings.TrimSpace(token)

	address, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("invalid recipient email: %w", err)
	}
	if address.Address != to {
		return fmt.Errorf("invalid recipient email: bare address required")
	}

	if token == "" {
		return fmt.Errorf("password reset token is required")
	}

	resetURL, err := m.buildPasswordResetURL(token)
	if err != nil {
		return err
	}

	payload := mailtrapTemplateRequest{
		From: mailtrapAddress{
			Email: m.fromEmail,
			Name:  m.fromName,
		},
		To: []mailtrapAddress{
			{
				Email: to,
			},
		},
		TemplateUUID: m.templateUUID,
		TemplateVariables: passwordResetTemplateVariables{
			UserEmail:     to,
			PassResetLink: resetURL,
		},
	}

	return m.send(ctx, payload)
}

func (m *MailtrapService) buildPasswordResetURL(token string) (string, error) {
	resetURL, err := url.Parse(m.passwordResetURL)
	if err != nil {
		return "", fmt.Errorf("invalid password reset url: %w", err)
	}
	if resetURL.Host == "" || (resetURL.Scheme != "http" && resetURL.Scheme != "https") {
		return "", fmt.Errorf("invalid password reset url: absolute http(s) URL required")
	}

	query := resetURL.Query()
	query.Set("token", token)
	resetURL.RawQuery = query.Encode()

	return resetURL.String(), nil
}

func (m *MailtrapService) send(ctx context.Context, payload mailtrapTemplateRequest) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal mailtrap payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create mailtrap request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send mailtrap request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Provider response bodies can echo recipient data. Keep PII out of
		// application logs while retaining the actionable HTTP status.
		return fmt.Errorf("mailtrap request failed with status %d", resp.StatusCode)
	}

	return nil
}

type mailtrapTemplateRequest struct {
	From              mailtrapAddress                `json:"from"`
	To                []mailtrapAddress              `json:"to"`
	TemplateUUID      string                         `json:"template_uuid"`
	TemplateVariables passwordResetTemplateVariables `json:"template_variables"`
}

type mailtrapAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type passwordResetTemplateVariables struct {
	UserEmail     string `json:"user_email"`
	PassResetLink string `json:"pass_reset_link"`
}
