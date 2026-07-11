package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleResetPassword(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "success",
			body:       `{"token":"valid-reset-token","password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusOK,
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBufferString(tt.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantError != "" {
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("unmarshaling response: %v", err)
				}
				if body.Error != tt.wantError {
					t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
				}
			}
		})
	}
}

func TestHandlePasswordChange(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		body       string
		wantStatus int
		wantError  string
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
		},
		{
			name:       "atomic database update fails",
			token:      "jwt_db_update_password_error",
			body:       `{"current_password":"password","new_password":"NewPassword1!","password_confirm":"NewPassword1!"}`,
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_update_password_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					Error string `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("unmarshaling response: %v", err)
				}
				if body.Error != tt.wantError {
					t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
				}
			}
		})
	}
}
