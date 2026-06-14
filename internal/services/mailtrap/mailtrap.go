// Package mailtrap provides a client for sending emails via the Mailtrap API.
package mailtrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type MailtrapService struct {
	apiKey       string
	apiURL       string
	fromEmail    string
	fromName     string
	resetURL     string
	templateUUID string
	httpClient   *http.Client
}

// NewMailtrapService creates a new email service instance
func NewMailtrapService() *MailtrapService {
	apiURL := os.Getenv("MAILTRAP_API_URL")
	if apiURL == "" {
		apiURL = "https://send.api.mailtrap.io/api/send" // Default to production
	}

	fromEmail := os.Getenv("EMAILS_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
	}

	fromName := os.Getenv("EMAILS_FROM_NAME")
	if fromName == "" {
		fromName = "IAM Service"
	}

	// Where the reset link in the email points. Must match the frontend for
	// the environment this instance serves — a staging IAM must not send
	// users to the production reset page.
	resetURL := os.Getenv("PASSWORD_RESET_URL")
	if resetURL == "" {
		resetURL = "https://meets.noura.software/reset-password"
	}

	templateUUID := os.Getenv("MAILTRAP_TEMPLATE_UUID")
	if templateUUID == "" {
		templateUUID = "76de4eda-254e-41ed-87f8-a2fe114b616b"
	}

	return &MailtrapService{
		apiKey:       os.Getenv("MAILTRAP_API_TOKEN"),
		apiURL:       apiURL,
		fromEmail:    fromEmail,
		fromName:     fromName,
		resetURL:     resetURL,
		templateUUID: templateUUID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type MailtrapRepository interface {
	SendPasswordResetEmail(to, token string) error
}

func (m *MailtrapService) SendPasswordResetEmail(to, token string) error {
	resetURL := fmt.Sprintf("%s?token=%s", m.resetURL, token)

	reqBody := map[string]interface{}{
		"from": map[string]string{
			"email": m.fromEmail,
			"name":  m.fromName,
		},
		"to": []map[string]string{
			{"email": to},
		},
		"template_uuid": m.templateUUID,
		"template_variables": map[string]string{
			"user_email":      to,
			"pass_reset_link": resetURL,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling email request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", m.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read response body for detailed error message. Recipient addresses
		// are deliberately kept out of logs and error strings (PII).
		var errBody bytes.Buffer
		if _, readErr := errBody.ReadFrom(resp.Body); readErr == nil {
			return fmt.Errorf("mailtrap API returned status %d: %s", resp.StatusCode, errBody.String())
		}
		return fmt.Errorf("mailtrap API returned status %d", resp.StatusCode)
	}

	return nil
}
