package mailtrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type MailtrapService struct {
	apiKey     string
	apiURL     string
	fromEmail  string
	fromName   string
	httpClient *http.Client
}

// NewMailtrapService creates a new email service instance
func NewMailtrapService() *MailtrapService {
	apiURL := os.Getenv("MAILTRAP_API_URL")
	if apiURL == "" {
		apiURL = "https://send.api.mailtrap.io/api/send" // Default to production
	}

	fromEmail := os.Getenv("MAILTRAP_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
	}

	fromName := os.Getenv("MAILTRAP_FROM_NAME")
	if fromName == "" {
		fromName = "IAM Service"
	}

	return &MailtrapService{
		apiKey:    os.Getenv("MAILTRAP_API_KEY"),
		apiURL:    apiURL,
		fromEmail: fromEmail,
		fromName:  fromName,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type MailtrapRepository interface {
	SendPasswordResetEmail(to, token string) error
}

func (m *MailtrapService) SendPasswordResetEmail(to, token string) error {
	log.Printf("[Mailtrap] Attempting to send email to: %s", to)
	log.Printf("[Mailtrap] Using API URL: %s", m.apiURL)
	log.Printf("[Mailtrap] API Key present: %v", m.apiKey != "")

	resetURL := fmt.Sprintf("https://meets.noura.software/reset-password?token=%s", token)

	reqBody := map[string]interface{}{
		"from": map[string]string{
			"email": m.fromEmail,
			"name":  m.fromName,
		},
		"to": []map[string]string{
			{"email": to},
		},
		"template_uuid": "76de4eda-254e-41ed-87f8-a2fe114b616b",
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
		log.Printf("[Mailtrap] HTTP request error: %v", err)
		return fmt.Errorf("sending email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read response body for detailed error message
		var errBody bytes.Buffer
		if _, readErr := errBody.ReadFrom(resp.Body); readErr == nil {
			errMsg := errBody.String()
			log.Printf("[Mailtrap] API error (status %d): %s", resp.StatusCode, errMsg)
			return fmt.Errorf("mailtrap API returned status %d: %s", resp.StatusCode, errMsg)
		}
		log.Printf("[Mailtrap] API error (status %d)", resp.StatusCode)
		return fmt.Errorf("mailtrap API returned status %d", resp.StatusCode)
	}

	log.Printf("[Mailtrap] Email sent successfully to: %s", to)
	return nil
}
