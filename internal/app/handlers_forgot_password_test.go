package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
)

type forgotPasswordDBStub struct {
	sqldb.Service
	getUserByEmailFn         func(context.Context, string) (models.User, error)
	createPasswordResetToken func(context.Context, models.NewPasswordResetToken) (models.PasswordResetToken, error)
}

func (s *forgotPasswordDBStub) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	if s.getUserByEmailFn == nil {
		panic("unexpected GetUserByEmail call")
	}
	return s.getUserByEmailFn(ctx, email)
}

func (s *forgotPasswordDBStub) CreatePasswordResetToken(
	ctx context.Context,
	token models.NewPasswordResetToken,
) (models.PasswordResetToken, error) {
	if s.createPasswordResetToken == nil {
		panic("unexpected CreatePasswordResetToken call")
	}
	return s.createPasswordResetToken(ctx, token)
}

type forgotPasswordMailerStub struct {
	sendFn func(context.Context, string, string) error
}

func (s *forgotPasswordMailerStub) SendPasswordResetEmail(ctx context.Context, to, token string) error {
	if s.sendFn == nil {
		panic("unexpected SendPasswordResetEmail call")
	}
	return s.sendFn(ctx, to, token)
}

func forgotPasswordRouter(a *App) *gin.Engine {
	router := gin.New()
	router.POST("/forgot", a.HandleForgotPassword)
	return router
}

func TestHandleForgotPasswordRejectsInvalidBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{`},
		{name: "missing email", body: `{}`},
		{name: "invalid email", body: `{"email":"not-an-email"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupCalls := 0
			db := &forgotPasswordDBStub{
				getUserByEmailFn: func(context.Context, string) (models.User, error) {
					lookupCalls++
					return models.User{}, nil
				},
			}
			a := NewApp(db, nil, nil, nil)

			request := httptest.NewRequest(http.MethodPost, "/forgot", bytes.NewBufferString(tt.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			forgotPasswordRouter(a).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusBadRequest, response.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshaling response: %v", err)
			}
			if body.Error != "invalid_request_body" {
				t.Fatalf("error = %q, want %q", body.Error, "invalid_request_body")
			}
			if lookupCalls != 0 {
				t.Fatalf("database lookups = %d, want 0", lookupCalls)
			}
		})
	}
}

func TestHandleForgotPasswordDoesNotRevealAccountState(t *testing.T) {
	const (
		requestEmail   = "USER@EXAMPLE.COM"
		normalized     = "user@example.com"
		genericMessage = "If the email exists, a password reset link has been sent"
	)

	errLookup := errors.New("lookup failed")
	errGenerate := errors.New("random source failed")
	errPersist := errors.New("persist failed")
	errSend := errors.New("send failed")

	tests := []struct {
		name             string
		lookupErr        error
		generateErr      error
		persistErr       error
		sendErr          error
		wantGenerate     int
		wantPersist      int
		wantSend         int
		wantPersistedTok bool
	}{
		{
			name:             "success",
			wantGenerate:     1,
			wantPersist:      1,
			wantSend:         1,
			wantPersistedTok: true,
		},
		{
			name:      "unknown account",
			lookupErr: sqldb.ErrDBNotFound,
		},
		{
			name:      "database lookup failure",
			lookupErr: errLookup,
		},
		{
			name:         "token generation failure",
			generateErr:  errGenerate,
			wantGenerate: 1,
		},
		{
			name:         "token persistence failure",
			persistErr:   errPersist,
			wantGenerate: 1,
			wantPersist:  1,
		},
		{
			name:             "email delivery failure",
			sendErr:          errSend,
			wantGenerate:     1,
			wantPersist:      1,
			wantSend:         1,
			wantPersistedTok: true,
		},
	}

	originalGenerateResetToken := generateResetToken
	t.Cleanup(func() { generateResetToken = originalGenerateResetToken })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generateCalls := 0
			persistCalls := 0
			sendCalls := 0
			var persisted models.NewPasswordResetToken
			var sentEmail string
			var sentToken string

			generateResetToken = func(length int) (string, error) {
				generateCalls++
				if length != resetTokenLength {
					t.Fatalf("token length argument = %d, want %d", length, resetTokenLength)
				}
				if tt.generateErr != nil {
					return "", tt.generateErr
				}
				return strings.Repeat("ab", length), nil
			}

			db := &forgotPasswordDBStub{
				getUserByEmailFn: func(_ context.Context, email string) (models.User, error) {
					if email != normalized {
						t.Fatalf("lookup email = %q, want %q", email, normalized)
					}
					if tt.lookupErr != nil {
						return models.User{}, tt.lookupErr
					}
					return models.User{ID: "user-id", Email: normalized}, nil
				},
				createPasswordResetToken: func(
					_ context.Context,
					token models.NewPasswordResetToken,
				) (models.PasswordResetToken, error) {
					persistCalls++
					persisted = token
					if tt.persistErr != nil {
						return models.PasswordResetToken{}, tt.persistErr
					}
					return models.PasswordResetToken{Token: token.Token}, nil
				},
			}
			mailer := &forgotPasswordMailerStub{
				sendFn: func(_ context.Context, email, token string) error {
					sendCalls++
					sentEmail = email
					sentToken = token
					return tt.sendErr
				},
			}
			a := NewApp(db, nil, mailer, nil)

			started := time.Now()
			request := httptest.NewRequest(
				http.MethodPost,
				"/forgot",
				bytes.NewBufferString(`{"email":"`+requestEmail+`"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			forgotPasswordRouter(a).ServeHTTP(response, request)
			finished := time.Now()

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
			}
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshaling response: %v", err)
			}
			if body.Message != genericMessage {
				t.Fatalf("message = %q, want %q", body.Message, genericMessage)
			}
			if generateCalls != tt.wantGenerate {
				t.Fatalf("token generation calls = %d, want %d", generateCalls, tt.wantGenerate)
			}
			if persistCalls != tt.wantPersist {
				t.Fatalf("token persistence calls = %d, want %d", persistCalls, tt.wantPersist)
			}
			if sendCalls != tt.wantSend {
				t.Fatalf("email send calls = %d, want %d", sendCalls, tt.wantSend)
			}

			if tt.wantPersistedTok {
				if persisted.UserID != "user-id" {
					t.Errorf("persisted user ID = %q, want %q", persisted.UserID, "user-id")
				}
				if persisted.Token != strings.Repeat("ab", resetTokenLength) {
					t.Errorf("persisted token = %q, want generated token", persisted.Token)
				}
				if persisted.ExpiresAt.Before(started.Add(resetTokenTTL)) ||
					persisted.ExpiresAt.After(finished.Add(resetTokenTTL)) {
					t.Errorf("expiry %s is not approximately one reset TTL from now", persisted.ExpiresAt)
				}
				if sentEmail != normalized {
					t.Errorf("email recipient = %q, want %q", sentEmail, normalized)
				}
				if sentToken != persisted.Token {
					t.Errorf("email token = %q, want persisted token %q", sentToken, persisted.Token)
				}
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := generateSecureToken(resetTokenLength)
	if err != nil {
		t.Fatalf("generateSecureToken returned error: %v", err)
	}
	if len(token) != resetTokenLength*2 {
		t.Fatalf("encoded token length = %d, want %d", len(token), resetTokenLength*2)
	}
	decoded, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not hexadecimal: %v", err)
	}
	if len(decoded) != resetTokenLength {
		t.Fatalf("decoded token length = %d, want %d", len(decoded), resetTokenLength)
	}
}

func TestGenerateSecureTokenReturnsRandomReadError(t *testing.T) {
	expectedErr := errors.New("random source unavailable")
	originalReadRandomBytes := readRandomBytes
	readRandomBytes = func([]byte) (int, error) {
		return 0, expectedErr
	}
	t.Cleanup(func() {
		readRandomBytes = originalReadRandomBytes
	})

	token, err := generateSecureToken(resetTokenLength)
	if token != "" {
		t.Fatalf("token = %q, want empty", token)
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("error = %v, want %v", err, expectedErr)
	}
}
