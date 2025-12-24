// Package mailtrap provides email sending functionality via Mailtrap API.
package mailtrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

var (
	apiKey = os.Getenv("MAILTRAP_API_KEY")
	url    = os.Getenv("MAILTRAP_API_URL")
)

type MailtrapService struct {
	APIKey string
	URL    string
}

func NewMailtrapService() *MailtrapService {
	return &MailtrapService{
		APIKey: apiKey,
		URL:    url,
	}
}

// EmailRecipient represents an email recipient
type EmailRecipient struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// EmailRequest represents the request payload for sending an email
type EmailRequest struct {
	From     EmailRecipient   `json:"from"`
	To       []EmailRecipient `json:"to"`
	Subject  string           `json:"subject"`
	HTML     string           `json:"html,omitempty"`
	Text     string           `json:"text,omitempty"`
	Category string           `json:"category,omitempty"`
}

// SendPasswordRecovery sends a password recovery email
func (m *MailtrapService) SendPasswordRecovery(toEmail, toName, resetToken, resetURL string) error {
	htmlBody := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Password Recovery</title>
		</head>
		<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
			<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
				<h2>Password Recovery Request</h2>
				<p>Hello %s,</p>
				<p>We received a request to reset your password. Click the button below to reset it:</p>
				<p style="margin: 30px 0;">
					<a href="%s" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
				</p>
				<p>Or copy and paste this link into your browser:</p>
				<p style="word-break: break-all; color: #007bff;">%s</p>
				<p>This link will expire in 1 hour.</p>
				<p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
				<hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
				<p style="font-size: 12px; color: #666;">This is an automated message, please do not reply.</p>
			</div>
		</body>
		</html>
	`, toName, resetURL, resetURL)

	textBody := fmt.Sprintf(`
Password Recovery Request

Hello %s,

We received a request to reset your password. Click the link below to reset it:

%s

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

---
This is an automated message, please do not reply.
	`, toName, resetURL)

	emailReq := EmailRequest{
		From: EmailRecipient{
			Email: "noreply@yourdomain.com",
			Name:  "Your App Name",
		},
		To: []EmailRecipient{
			{
				Email: toEmail,
				Name:  toName,
			},
		},
		Subject:  "Password Recovery Request",
		HTML:     htmlBody,
		Text:     textBody,
		Category: "password_recovery",
	}

	return m.sendEmail(emailReq)
}

// sendEmail sends an email via the Mailtrap API
func (m *MailtrapService) sendEmail(emailReq EmailRequest) error {
	payload, err := json.Marshal(emailReq)
	if err != nil {
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	req, err := http.NewRequest("POST", m.URL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("mailtrap API returned status: %d", resp.StatusCode)
	}

	return nil
}
