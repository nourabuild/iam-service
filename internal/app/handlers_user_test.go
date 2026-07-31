package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/kafka"
)

type userHandlerDBStub struct {
	sqldb.Service
	updateUser  func(context.Context, string, models.UpdateUser, sqldb.OutboxEventFunc) (models.User, error)
	getUserByID func(context.Context, string) (models.User, error)
	listUsers   func(context.Context) ([]models.User, error)
}

func (s userHandlerDBStub) UpdateUser(
	ctx context.Context,
	userID string,
	update models.UpdateUser,
	eventFn sqldb.OutboxEventFunc,
) (models.User, error) {
	return s.updateUser(ctx, userID, update, eventFn)
}

func (s userHandlerDBStub) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	return s.getUserByID(ctx, userID)
}

func (s userHandlerDBStub) ListUsers(ctx context.Context) ([]models.User, error) {
	return s.listUsers(ctx)
}

func performUserHandlerRequest(t *testing.T, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var requestBody io.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, requestBody)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

func newUserHandlerContext(method, target, body string) (*gin.Context, *httptest.ResponseRecorder) {
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)

	var requestBody io.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	c.Request = httptest.NewRequest(method, target, requestBody)
	if body != "" {
		c.Request.Header.Set("Content-Type", "application/json")
	}

	return c, response
}

func assertUserHandlerError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantError string,
	wantDetails map[string]string,
) {
	t.Helper()

	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body: %s)", response.Code, wantStatus, response.Body.String())
	}

	var body struct {
		Error   string            `json:"error"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if body.Error != wantError {
		t.Errorf("error = %q, want %q", body.Error, wantError)
	}
	if !reflect.DeepEqual(body.Details, wantDetails) {
		t.Errorf("details = %#v, want %#v", body.Details, wantDetails)
	}
}

func TestUserUpdatedOutbox(t *testing.T) {
	bio := "Builds reliable systems"
	dob := "1990-01-02"
	city := "Portland"
	phone := "+1-555-0100"
	avatarPhotoID := 42
	user := models.User{
		ID:            "user-123",
		Name:          "Ada Lovelace",
		Email:         "ada@example.com",
		Account:       "adalovelace",
		Bio:           &bio,
		DOB:           &dob,
		City:          &city,
		Phone:         &phone,
		AvatarPhotoID: &avatarPhotoID,
		IsAdmin:       true,
		Role:          models.RoleAdmin,
	}

	before := time.Now().UTC()
	message := userUpdatedOutbox("request-123")(user)
	after := time.Now().UTC()

	if message.Topic != kafka.ProduceTopicUserUpdated {
		t.Errorf("topic = %q, want %q", message.Topic, kafka.ProduceTopicUserUpdated)
	}
	if message.Key != user.ID {
		t.Errorf("key = %q, want %q", message.Key, user.ID)
	}
	if got := message.Headers[kafka.HeaderCorrelationID]; got != "request-123" {
		t.Errorf("correlation header = %q, want %q", got, "request-123")
	}

	event, ok := message.Payload.(models.UserUpdatedEvent)
	if !ok {
		t.Fatalf("payload type = %T, want models.UserUpdatedEvent", message.Payload)
	}
	if event.EventType != "UserUpdated" {
		t.Errorf("event type = %q, want UserUpdated", event.EventType)
	}
	if event.UserID != user.ID ||
		event.Name != user.Name ||
		event.Email != user.Email ||
		event.Account != user.Account ||
		event.Bio != user.Bio ||
		event.DOB != user.DOB ||
		event.City != user.City ||
		event.Phone != user.Phone ||
		event.AvatarPhotoID != user.AvatarPhotoID ||
		event.IsAdmin != user.IsAdmin ||
		event.Role != user.Role {
		t.Errorf("event payload = %#v, want fields copied from %#v", event, user)
	}
	if event.OccurredAt.Before(before) || event.OccurredAt.After(after) {
		t.Errorf("occurred_at = %s, want between %s and %s", event.OccurredAt, before, after)
	}
	if event.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at location = %v, want UTC", event.OccurredAt.Location())
	}

	fallbackMessage := userUpdatedOutbox("")(user)
	if got := fallbackMessage.Headers[kafka.HeaderCorrelationID]; got != user.ID {
		t.Errorf("fallback correlation header = %q, want %q", got, user.ID)
	}
}

func TestHandleUpdateAccount(t *testing.T) {
	const uri = "/api/v1/user/me/account"

	t.Run("missing principal", func(t *testing.T) {
		c, response := newUserHandlerContext(
			http.MethodPost,
			uri,
			`{"name":"Ada Lovelace","account":"adalovelace"}`,
		)

		(&App{}).HandleUpdateAccount(c)

		assertUserHandlerError(t, response, http.StatusUnauthorized, "unauthorized", nil)
	})

	tests := []struct {
		name        string
		body        string
		wantStatus  int
		wantError   string
		wantDetails map[string]string
	}{
		{
			name:       "malformed JSON",
			body:       `{"name":`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request_body",
		},
		{
			name:       "whitespace required fields",
			body:       `{"name":"  ","account":"  "}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "missing_required_fields",
			wantDetails: map[string]string{
				"name":    "name_required",
				"account": "account_required",
			},
		},
		{
			name:       "account too short",
			body:       `{"name":"Ada Lovelace","account":"short"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "missing_required_fields",
			wantDetails: map[string]string{
				"account": "account_too_short",
			},
		},
		{
			name:       "account already taken",
			body:       `{"name":"Ada Lovelace","account":"taken_account"}`,
			wantStatus: http.StatusConflict,
			wantError:  "account_already_taken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performUserHandlerRequest(t, http.MethodPost, uri, "valid-access-token", tt.body)
			assertUserHandlerError(t, response, tt.wantStatus, tt.wantError, tt.wantDetails)
		})
	}

	t.Run("database failure", func(t *testing.T) {
		db := userHandlerDBStub{
			updateUser: func(
				context.Context,
				string,
				models.UpdateUser,
				sqldb.OutboxEventFunc,
			) (models.User, error) {
				return models.User{}, errors.New("update failed")
			},
		}
		c, response := newUserHandlerContext(
			http.MethodPost,
			uri,
			`{"name":"Ada Lovelace","account":"adalovelace"}`,
		)
		middleware.SetPrincipal(c, models.Principal{ID: "user-123", Role: models.RoleUser})

		(&App{db: db}).HandleUpdateAccount(c)

		assertUserHandlerError(
			t,
			response,
			http.StatusInternalServerError,
			"internal_update_account_error",
			nil,
		)
	})

	t.Run("success trims fields", func(t *testing.T) {
		response := performUserHandlerRequest(
			t,
			http.MethodPost,
			uri,
			"valid-access-token",
			`{"name":"  Ada Lovelace  ","account":"  adalovelace  ","bio":"Builds reliable systems"}`,
		)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
		}

		var user models.User
		if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if user.ID != "user-id" {
			t.Errorf("user ID = %q, want user-id", user.ID)
		}
		if user.Name != "Ada Lovelace" {
			t.Errorf("name = %q, want trimmed name", user.Name)
		}
		if user.Account != "adalovelace" {
			t.Errorf("account = %q, want trimmed account", user.Account)
		}
		if user.Bio == nil || *user.Bio != "Builds reliable systems" {
			t.Errorf("bio = %#v, want supplied bio", user.Bio)
		}
	})
}

func TestHandleMe(t *testing.T) {
	const uri = "/api/v1/user/me"

	t.Run("missing principal", func(t *testing.T) {
		c, response := newUserHandlerContext(http.MethodGet, uri, "")

		(&App{}).HandleMe(c)

		assertUserHandlerError(t, response, http.StatusUnauthorized, "unauthorized", nil)
	})

	tests := []struct {
		name       string
		dbError    error
		wantStatus int
		wantError  string
	}{
		{
			name:       "user not found",
			dbError:    sqldb.ErrDBNotFound,
			wantStatus: http.StatusUnauthorized,
			wantError:  "user_not_found",
		},
		{
			name:       "database failure",
			dbError:    errors.New("lookup failed"),
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_verify_user_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := userHandlerDBStub{
				getUserByID: func(context.Context, string) (models.User, error) {
					return models.User{}, tt.dbError
				},
			}
			c, response := newUserHandlerContext(http.MethodGet, uri, "")
			middleware.SetPrincipal(c, models.Principal{ID: "user-123", Role: models.RoleUser})

			(&App{db: db}).HandleMe(c)

			assertUserHandlerError(t, response, tt.wantStatus, tt.wantError, nil)
		})
	}

	t.Run("success", func(t *testing.T) {
		response := performUserHandlerRequest(t, http.MethodGet, uri, "valid-access-token", "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
		}

		var user models.User
		if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if user.ID != "user-id" || user.Account != "test-user" || user.Role != models.RoleUser {
			t.Errorf("user = %#v, want mock user", user)
		}
	})
}

func TestHandleListUsers(t *testing.T) {
	const uri = "/api/v1/admin/users"

	t.Run("database failure", func(t *testing.T) {
		db := userHandlerDBStub{
			listUsers: func(context.Context) ([]models.User, error) {
				return nil, errors.New("list failed")
			},
		}
		c, response := newUserHandlerContext(http.MethodGet, uri, "")

		(&App{db: db}).HandleListUsers(c)

		assertUserHandlerError(
			t,
			response,
			http.StatusInternalServerError,
			"internal_retrieve_users_error",
			nil,
		)
	})

	t.Run("success", func(t *testing.T) {
		response := performUserHandlerRequest(t, http.MethodGet, uri, "jwt_admin_access_token", "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
		}

		var users []models.User
		if err := json.Unmarshal(response.Body.Bytes(), &users); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("users length = %d, want 1", len(users))
		}
		if users[0].ID != "user-id" || users[0].Role != models.RoleUser {
			t.Errorf("user = %#v, want mock user", users[0])
		}
	})
}

func TestHandleGrantAdminRole(t *testing.T) {
	t.Run("empty user ID", func(t *testing.T) {
		c, response := newUserHandlerContext(http.MethodPost, "/api/v1/admin//roles/grant", "")

		(&App{}).HandleGrantAdminRole(c)

		assertUserHandlerError(t, response, http.StatusBadRequest, "invalid_user_id", nil)
	})

	tests := []struct {
		name       string
		userID     string
		wantStatus int
		wantError  string
	}{
		{
			name:       "user not found",
			userID:     "missing_user",
			wantStatus: http.StatusNotFound,
			wantError:  "user_not_found",
		},
		{
			name:       "database failure",
			userID:     "db_promote_user_error",
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_promote_user_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performUserHandlerRequest(
				t,
				http.MethodPost,
				"/api/v1/admin/"+tt.userID+"/roles/grant",
				"jwt_admin_access_token",
				"",
			)
			assertUserHandlerError(t, response, tt.wantStatus, tt.wantError, nil)
		})
	}

	t.Run("success", func(t *testing.T) {
		response := performUserHandlerRequest(
			t,
			http.MethodPost,
			"/api/v1/admin/user-123/roles/grant",
			"jwt_admin_access_token",
			"",
		)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
		}

		var user models.User
		if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if user.ID != "user-123" || !user.IsAdmin || user.Role != models.RoleAdmin {
			t.Errorf("user = %#v, want promoted admin", user)
		}
	})
}

func TestHandleRevokeAdminRole(t *testing.T) {
	t.Run("empty user ID", func(t *testing.T) {
		c, response := newUserHandlerContext(http.MethodPost, "/api/v1/admin//roles/revoke", "")

		(&App{}).HandleRevokeAdminRole(c)

		assertUserHandlerError(t, response, http.StatusBadRequest, "invalid_user_id", nil)
	})

	tests := []struct {
		name       string
		userID     string
		wantStatus int
		wantError  string
	}{
		{
			name:       "user not found",
			userID:     "missing_user",
			wantStatus: http.StatusNotFound,
			wantError:  "user_not_found",
		},
		{
			name:       "database failure",
			userID:     "db_demote_user_error",
			wantStatus: http.StatusInternalServerError,
			wantError:  "internal_demote_user_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performUserHandlerRequest(
				t,
				http.MethodPost,
				"/api/v1/admin/"+tt.userID+"/roles/revoke",
				"jwt_admin_access_token",
				"",
			)
			assertUserHandlerError(t, response, tt.wantStatus, tt.wantError, nil)
		})
	}

	t.Run("success", func(t *testing.T) {
		response := performUserHandlerRequest(
			t,
			http.MethodPost,
			"/api/v1/admin/user-123/roles/revoke",
			"jwt_admin_access_token",
			"",
		)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
		}

		var user models.User
		if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if user.ID != "user-123" || user.IsAdmin || user.Role != models.RoleUser {
			t.Errorf("user = %#v, want demoted regular user", user)
		}
	})
}
