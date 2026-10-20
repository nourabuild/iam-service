// Package mailtrap sends transactional email through the Mailtrap API.
package mailtrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

// Client sends transactional messages through Mailtrap.
type Client struct {
	apiToken         string
	apiURL           string
	fromEmail        string
	fromName         string
	templateUUID     string
	passwordResetURL string
	httpClient       *http.Client
}

// New constructs a Mailtrap Client from cfg.
func New(cfg config.Mailtrap) *Client {
	return &Client{
		apiToken:         cfg.APIToken,
		apiURL:           cfg.APIURL,
		fromEmail:        cfg.SenderEmail,
		fromName:         cfg.SenderName,
		templateUUID:     cfg.TemplateUUID,
		passwordResetURL: cfg.PasswordResetURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// Never forward the bearer API token through a provider redirect.
			// A redirect response is handled as a delivery failure below.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SendPasswordResetEmail sends a password-reset link to a bare email address.
func (c *Client) SendPasswordResetEmail(ctx context.Context, to, token string) error {
	to = strings.TrimSpace(to)
	token = strings.TrimSpace(token)

	if strings.TrimSpace(c.apiToken) == "" {
		return errors.New("mailtrap API token is not configured")
	}

	address, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("invalid recipient email: %w", err)
	}
	if address.Address != to {
		return errors.New("invalid recipient email: bare address required")
	}

	if token == "" {
		return errors.New("password reset token is required")
	}

	resetURL, err := c.buildPasswordResetURL(token)
	if err != nil {
		return err
	}

	payload := mailtrapTemplateRequest{
		From: mailtrapAddress{
			Email: c.fromEmail,
			Name:  c.fromName,
		},
		To: []mailtrapAddress{
			{
				Email: to,
			},
		},
		TemplateUUID: c.templateUUID,
		TemplateVariables: passwordResetTemplateVariables{
			UserEmail:     to,
			PassResetLink: resetURL,
		},
	}

	return c.send(ctx, payload)
}

func (c *Client) buildPasswordResetURL(token string) (string, error) {
	resetURL, err := url.Parse(c.passwordResetURL)
	if err != nil {
		return "", fmt.Errorf("invalid password reset url: %w", err)
	}
	if resetURL.Host == "" || (resetURL.Scheme != "http" && resetURL.Scheme != "https") {
		return "", errors.New("invalid password reset url: absolute http(s) URL required")
	}

	query := resetURL.Query()
	query.Set("token", token)
	resetURL.RawQuery = query.Encode()

	return resetURL.String(), nil
}

func (c *Client) send(ctx context.Context, payload mailtrapTemplateRequest) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal mailtrap payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create mailtrap request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send mailtrap request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain normal provider responses so the transport can safely reuse the
	// underlying connection. Bound the read in case a broken endpoint returns
	// an unexpectedly large body.
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)); err != nil {
		return fmt.Errorf("read mailtrap response: %w", err)
	}

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
