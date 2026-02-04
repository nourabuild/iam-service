// Package mailtrap provides email sending functionality using Mailtrap API for the IAM service.
package mailtrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
)

// Service defines the email service interface
type Service interface {
	SendPasswordResetEmail(to, resetToken string) error
}

type service struct {
	apiKey     string
	apiURL     string
	fromEmail  string
	fromName   string
	httpClient *http.Client
}

// MailtrapRequest represents the structure for Mailtrap API requests
type MailtrapRequest struct {
	From     EmailAddress   `json:"from"`
	To       []EmailAddress `json:"to"`
	Subject  string         `json:"subject"`
	Text     string         `json:"text,omitempty"`
	HTML     string         `json:"html,omitempty"`
	Category string         `json:"category,omitempty"`
}

// EmailAddress represents an email address with optional name
type EmailAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// New creates a new email service instance
func NewMailtrapService() Service {
	return &service{
		apiKey:    os.Getenv("MAILTRAP_API_KEY"),
		apiURL:    os.Getenv("MAILTRAP_API_URL"),
		fromEmail: getEnvOrDefault("EMAIL_FROM", "noreply@example.com"),
		fromName:  getEnvOrDefault("EMAIL_FROM_NAME", "IAM Service"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendPasswordResetEmail sends a password reset email with the reset token
func (s *service) SendPasswordResetEmail(to, resetToken string) error {
	// Construct reset URL (in production, this would be your frontend URL)
	resetURL := fmt.Sprintf("%s/reset-password?token=%s",
		getEnvOrDefault("FRONTEND_URL", "http://localhost:3000"),
		resetToken,
	)

	subject := "Password Reset Request"
	text := fmt.Sprintf(`Hello,

You have requested to reset your password. Please click the link below to reset your password:

%s

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.

Best regards,
IAM Service Team`, resetURL)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h2 style="color: #333; margin-top: 0;">Password Reset Request</h2>
        <p>Hello,</p>
        <p>You have requested to reset your password. Please click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #007bff;">%s</p>
        <p style="margin-top: 20px; font-size: 14px; color: #666;">
            <strong>This link will expire in 1 hour.</strong>
        </p>
        <p style="font-size: 14px; color: #666;">
            If you did not request a password reset, please ignore this email.
        </p>
    </div>
    <div style="font-size: 12px; color: #999; text-align: center;">
        <p>Best regards,<br>IAM Service Team</p>
    </div>
</body>
</html>`, resetURL, resetURL)

	return s.sendEmail(MailtrapRequest{
		From: EmailAddress{
			Email: s.fromEmail,
			Name:  s.fromName,
		},
		To: []EmailAddress{
			{Email: to},
		},
		Subject:  subject,
		Text:     text,
		HTML:     html,
		Category: "password_reset",
	})
}

// sendEmail sends an email using the Mailtrap API
func (s *service) sendEmail(req MailtrapRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling email request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", s.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mailtrap API returned status %d", resp.StatusCode)
	}

	return nil
}

// getEnvOrDefault returns the environment variable value or a default value if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
