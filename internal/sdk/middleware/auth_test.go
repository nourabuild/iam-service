package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

// newTokenService builds a real TokenService so the middleware tests exercise
// actual JWT parsing rather than a mock's approximation of it.
func newTokenService(t *testing.T) *jwt.TokenService {
	t.Helper()

	return jwt.NewTokenService(config.AuthConfig{
		JWTSecret:       "middleware-test-access-secret-0123456789",
		Issuer:          "middleware-test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
}

func newAuthEngine(svc jwt.TokenRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", Authenticate(svc), func(c *gin.Context) {
		userID, err := GetUserID(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no_user_in_context"})
			return
		}
		role, _ := c.Get(RoleKey)
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "role": role})
	})
	return r
}

func TestAuthenticate(t *testing.T) {
	svc := newTokenService(t)
	engine := newAuthEngine(svc)

	validToken, _, err := svc.IssueAccessToken(models.User{ID: "user-123", IsAdmin: true, Role: models.RoleAdmin}, time.Now().UTC())
	if err != nil {
		t.Fatalf("generating valid token: %v", err)
	}

	expiredSvc := jwt.NewTokenService(config.AuthConfig{
		JWTSecret:       "middleware-test-access-secret-0123456789",
		Issuer:          "middleware-test",
		AccessTokenTTL:  -time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
	expiredToken, _, err := expiredSvc.IssueAccessToken(models.User{ID: "user-123", Role: models.RoleUser}, time.Now().UTC())
	if err != nil {
		t.Fatalf("generating expired token: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing_authorization_header",
		},
		{
			name:           "wrong scheme",
			authHeader:     "Token " + validToken,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_authorization_header",
		},
		{
			name:           "empty token after scheme",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_authorization_header",
		},
		{
			name:           "garbage token",
			authHeader:     "Bearer not-a-jwt",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "unauthorized",
		},
		{
			name:           "expired token",
			authHeader:     "Bearer " + expiredToken,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "unauthorized",
		},
		{
			name:           "valid token",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "lowercase bearer scheme accepted",
			authHeader:     "bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshaling response: %v", err)
			}

			if tt.expectedError != "" {
				if body["error"] != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, body["error"])
				}
				return
			}

			if body["user_id"] != "user-123" {
				t.Errorf("expected user_id user-123 in context, got %v", body["user_id"])
			}
			if body["role"] != string(models.RoleAdmin) {
				t.Errorf("expected role admin in context, got %v", body["role"])
			}
		})
	}
}

func TestGetUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("missing", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if _, err := GetUserID(c); err == nil {
			t.Fatal("expected error when user_id absent, got nil")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set(UserIDKey, 42)
		if _, err := GetUserID(c); err == nil {
			t.Fatal("expected error for non-string user_id, got nil")
		}
	})

	t.Run("present", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		SetPrincipal(c, models.Principal{ID: "user-123", Role: models.RoleUser})
		id, err := GetUserID(c)
		if err != nil {
			t.Fatalf("GetUserID returned error: %v", err)
		}
		if id != "user-123" {
			t.Fatalf("expected user-123, got %q", id)
		}
	})
}
