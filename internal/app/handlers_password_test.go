package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
)

func TestHandleResetPassword(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		body           string
		forceHashError bool
		wantStatus     int
		wantError      string
		wantDetails    map[string]string
	}{
		{
			name:       "success",
			body:       `{"token":"valid-reset-token","password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "query token fallback",
			target:     "/api/v1/auth/password/reset?token=valid-reset-token",
			body:       `{"password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "malformed JSON",
			body:       `{`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request_body",
		},
		{
			name:       "missing token",
			body:       `{"password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "missing_reset_token",
			wantDetails: map[string]string{
				"token": "token_required",
			},
		},
		{
			name:       "invalid token",
			body:       `{"token":"invalid-reset-token","password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_or_expired_reset_token",
		},
		{
			name:       "database failure",
			body:       `{"token":"db_get_reset_token_error","password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_reset_password_error",
		},
		{
			name:       "password mismatch",
			body:       `{"token":"valid-reset-token","password":"NewPassword1!","password_confirm":"Different1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_mismatch",
			wantDetails: map[string]string{
				"field": "password_confirm",
			},
		},
		{
			name:       "password too short",
			body:       `{"token":"valid-reset-token","password":"A1!","password_confirm":"A1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_too_short",
		},
		{
			name:       "password too long",
			body:       `{"token":"valid-reset-token","password":"` + strings.Repeat("A", maxPasswordLength+1) + `","password_confirm":"` + strings.Repeat("A", maxPasswordLength+1) + `"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_too_long",
		},
		{
			name:       "password missing uppercase",
			body:       `{"token":"valid-reset-token","password":"password1!","password_confirm":"password1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_uppercase",
		},
		{
			name:       "password missing number",
			body:       `{"token":"valid-reset-token","password":"Password!","password_confirm":"Password!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_number",
		},
		{
			name:       "password missing special character",
			body:       `{"token":"valid-reset-token","password":"Password1","password_confirm":"Password1"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_special_character",
		},
		{
			name:           "hash failure",
			body:           `{"token":"valid-reset-token","password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			forceHashError: true,
			wantStatus:     http.StatusInternalServerError,
			wantError:      "internal_hash_error",
		},
	}

	originalGenerateFromPassword := generateFromPassword
	t.Cleanup(func() { generateFromPassword = originalGenerateFromPassword })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generateFromPassword = originalGenerateFromPassword
			if tt.forceHashError {
				generateFromPassword = func([]byte, int) ([]byte, error) {
					return nil, errors.New("hash failed")
				}
			}

			target := tt.target
			if target == "" {
				target = "/api/v1/auth/password/reset"
			}
			request := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(tt.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantError != "" {
				var body struct {
					Error   string            `json:"error"`
					Details map[string]string `json:"details"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("unmarshaling response: %v", err)
				}
				if body.Error != tt.wantError {
					t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
				}
				if !reflect.DeepEqual(body.Details, tt.wantDetails) {
					t.Fatalf("details = %#v, want %#v", body.Details, tt.wantDetails)
				}
			}
		})
	}
}

func TestHandlePasswordChange(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		body           string
		forceHashError bool
		wantStatus     int
		wantError      string
		wantDetails    map[string]string
	}{
		{
			name:       "success",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "wrong current password",
			token:      "valid-access-token",
			body:       `{"current_password":"wrong","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_mismatch",
			wantDetails: map[string]string{
				"field": "current_password",
			},
		},
		{
			name:       "atomic database update fails",
			token:      "jwt_db_update_password_error",
			body:       `{"current_password":"password","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_update_password_error",
		},
		{
			name:       "malformed JSON",
			token:      "valid-access-token",
			body:       `{`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request_body",
		},
		{
			name:       "missing required fields",
			token:      "valid-access-token",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "missing_required_fields",
			wantDetails: map[string]string{
				"current_password": "current_password_required",
				"new_password":     "new_password_required",
				"password_confirm": "password_confirm_required",
			},
		},
		{
			name:       "new passwords mismatch",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"NewPassword1!","password_confirm":"Different1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_mismatch",
			wantDetails: map[string]string{
				"field": "password_confirm",
			},
		},
		{
			name:       "new password too short",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"A1!","password_confirm":"A1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_too_short",
		},
		{
			name:       "new password too long",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"` + strings.Repeat("A", maxPasswordLength+1) + `","password_confirm":"` + strings.Repeat("A", maxPasswordLength+1) + `"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_too_long",
		},
		{
			name:       "new password missing uppercase",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"password1!","password_confirm":"password1!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_uppercase",
		},
		{
			name:       "new password missing number",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"Password!","password_confirm":"Password!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_number",
		},
		{
			name:       "new password missing special character",
			token:      "valid-access-token",
			body:       `{"current_password":"password","new_password":"Password1","password_confirm":"Password1"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "password_must_contain_special_character",
		},
		{
			name:           "hash failure",
			token:          "valid-access-token",
			body:           `{"current_password":"password","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			forceHashError: true,
			wantStatus:     http.StatusInternalServerError,
			wantError:      "internal_hash_error",
		},
	}

	originalGenerateFromPassword := generateFromPassword
	t.Cleanup(func() { generateFromPassword = originalGenerateFromPassword })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generateFromPassword = originalGenerateFromPassword
			if tt.forceHashError {
				generateFromPassword = func([]byte, int) ([]byte, error) {
					return nil, errors.New("hash failed")
				}
			}

			request := httptest.NewRequest(http.MethodPost, "/api/v1/user/me/password/change", bytes.NewBufferString(tt.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+tt.token)
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantError != "" {
				var body struct {
					Error   string            `json:"error"`
					Details map[string]string `json:"details"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("unmarshaling response: %v", err)
				}
				if body.Error != tt.wantError {
					t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
				}
				if !reflect.DeepEqual(body.Details, tt.wantDetails) {
					t.Fatalf("details = %#v, want %#v", body.Details, tt.wantDetails)
				}
			}
		})
	}
}

type passwordChangeDBStub struct {
	sqldb.Service
	getUserByIDFn                       func(context.Context, string) (models.User, error)
	updateUserPasswordAndRevokeTokensFn func(context.Context, string, []byte) error
}

func (s *passwordChangeDBStub) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	if s.getUserByIDFn == nil {
		panic("unexpected GetUserByID call")
	}
	return s.getUserByIDFn(ctx, userID)
}

func (s *passwordChangeDBStub) UpdateUserPasswordAndRevokeTokens(
	ctx context.Context,
	userID string,
	password []byte,
) error {
	if s.updateUserPasswordAndRevokeTokensFn == nil {
		panic("unexpected UpdateUserPasswordAndRevokeTokens call")
	}
	return s.updateUserPasswordAndRevokeTokensFn(ctx, userID, password)
}

func passwordChangeRouter(a *App, userID string) *gin.Engine {
	router := gin.New()
	router.POST("/change", func(c *gin.Context) {
		if userID != "" {
			middleware.SetPrincipal(c, models.Principal{ID: userID, Role: models.RoleUser})
		}
		a.HandlePasswordChange(c)
	})
	return router
}

func TestHandlePasswordChangeIdentityAndDatabaseFailures(t *testing.T) {
	dbFailure := errors.New("database unavailable")
	tests := []struct {
		name       string
		userID     string
		getUserErr error
		wantStatus int
		wantError  string
		wantReads  int
	}{
		{
			name:       "missing principal",
			wantStatus: http.StatusUnauthorized,
			wantError:  "unauthorized",
		},
		{
			name:       "user no longer exists",
			userID:     "missing-user",
			getUserErr: sqldb.ErrDBNotFound,
			wantStatus: http.StatusUnauthorized,
			wantError:  "user_not_found",
			wantReads:  1,
		},
		{
			name:       "database read failure",
			userID:     "user-id",
			getUserErr: dbFailure,
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_update_password_error",
			wantReads:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readCalls := 0
			db := &passwordChangeDBStub{
				getUserByIDFn: func(context.Context, string) (models.User, error) {
					readCalls++
					return models.User{}, tt.getUserErr
				},
			}
			a := NewApp(db, nil, nil, nil)

			request := httptest.NewRequest(
				http.MethodPost,
				"/change",
				bytes.NewBufferString(
					`{"current_password":"password","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
				),
			)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			passwordChangeRouter(a, tt.userID).ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, tt.wantStatus, response.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshaling response: %v", err)
			}
			if body.Error != tt.wantError {
				t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
			}
			if readCalls != tt.wantReads {
				t.Fatalf("database reads = %d, want %d", readCalls, tt.wantReads)
			}
		})
	}
}
