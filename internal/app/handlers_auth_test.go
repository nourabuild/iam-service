package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var loginTests = []struct {
	body               string
	requestID          string
	expectedStatusCode int
	expectedResponse   string
}{
	{
		body:               `{"email": "user@example.com", "password": "password"}`,
		expectedStatusCode: http.StatusOK,
		expectedResponse:   `{"access_token": "accessToken", "refresh_token": "refreshToken"}`,
	},
	{
		body:               ``,
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse:   `{"error": "invalid_request_body"}`,
	},
	{
		body:               `{"email": "", "password": ""}`,
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
            "error":"missing_required_fields",
            "details": {
                "email": "email_required",
                "password": "password_required"
            }
        }`,
	},
	{
		body:               `{"email": "user@example.com", "password": "wrong"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "invalid_credentials"}`,
	},
	{
		body:               `{"email": "missing_user@test.loc", "password": "password"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "invalid_credentials"}`,
	},
	{
		body:               `{"email": "db_get_user_error@test.loc", "password": "password"}`,
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_login_error"}`,
	},
	{
		body:               `{"email": "jwt_generate_tokens_error@test.loc", "password": "password"}`,
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_generate_tokens_error"}`,
	},
	{
		body:               `{"email": "db_create_refresh_token_error@test.loc", "password": "password"}`,
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_generate_tokens_error"}`,
	},
	{
		body:               `{"email": "user@example.com",`,
		requestID:          "req-login-unmarshal",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse:   `{"error": "invalid_request_body"}`,
	},
}

func TestHandleLogin(t *testing.T) {
	var uri = "/api/v1/auth/login"

	for _, tt := range loginTests {

		body := []byte(tt.body)
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		if tt.requestID != "" {
			req.Header.Set("X-Request-ID", tt.requestID)
		}

		rr := httptest.NewRecorder()

		engine.ServeHTTP(rr, req)

		if tt.expectedStatusCode != rr.Code {
			log.Println(body)
			log.Printf("error msg: %v", rr.Body.String())
			t.Errorf("received wrong status code. expected: %v, actual: %v", tt.expectedStatusCode, rr.Code)
		}

		if tt.expectedStatusCode == http.StatusOK {
			var actual TokenResponse
			json.Unmarshal(rr.Body.Bytes(), &actual)

			var expected TokenResponse
			json.Unmarshal([]byte(tt.expectedResponse), &expected)

			if expected.AccessToken != actual.AccessToken {
				t.Errorf("received wrong accessToken. expected: %v, actual: %v", expected.AccessToken, actual.AccessToken)
			}
			if expected.RefreshToken != actual.RefreshToken {
				t.Errorf("received wrong refreshToken. expected: %v, actual: %v", expected.RefreshToken, actual.RefreshToken)
			}
			continue
		}

		// Validate failure branches / bad requests
		var actual map[string]interface{}
		var expected map[string]interface{}

		err := json.Unmarshal(rr.Body.Bytes(), &actual)
		assert.NoError(t, err)

		err = json.Unmarshal([]byte(tt.expectedResponse), &expected)
		assert.NoError(t, err)

		assert.Equal(t, expected, actual)
	}
}

var registerTests = []struct {
	body               string
	contentType        string
	forceHashError     bool
	expectedStatusCode int
	expectedResponse   string
}{
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusCreated,
		expectedResponse:   `{"access_token": "accessToken", "refresh_token": "refreshToken"}`,
	},
	{
		body:               "--AaB03x\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nJohn Doe\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"account\"\r\n\r\njohndoe\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nuser@example.com\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nPassword1!\r\n--AaB03x--\r\n",
		contentType:        "multipart/form-data; boundary=AaB03x",
		expectedStatusCode: http.StatusCreated,
		expectedResponse:   `{"access_token": "accessToken", "refresh_token": "refreshToken"}`,
	},
	{
		body:               `--bad-multipart-body`,
		contentType:        "multipart/form-data",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse:   `{"error": "invalid_request_body"}`,
	},
	{
		body:               ``,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"missing_required_fields",
			"details": {
				"name": "name_required",
				"account": "account_required",
				"email": "email_required",
				"password": "password_required"
			}
		}`,
	},
	{
		body:               `name=&account=&email=&password=`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"missing_required_fields",
			"details": {
				"name": "name_required",
				"account": "account_required",
				"email": "email_required",
				"password": "password_required"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=weak`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"password_too_short",
			"details": {
				"password": "password_too_short"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=bad-email&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"invalid_email",
			"details": {
				"email": "invalid_email_format"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=john&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"account_too_short",
			"details": {
				"account": "account_too_short"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"password_must_contain_uppercase",
			"details": {
				"password": "password_no_uppercase"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=Password%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"password_must_contain_number",
			"details": {
				"password": "password_no_number"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=Password1`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"password_must_contain_special_character",
			"details": {
				"password": "password_no_special_char"
			}
		}`,
	},
	{
		body:               `name=John+Doe&account=duplicated_user&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusConflict,
		expectedResponse:   `{"error": "user_already_exists"}`,
	},
	{
		body:               `name=John+Doe&account=db_create_user_error&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_create_user_error"}`,
	},
	{
		body:               `name=John+Doe&account=johndoe&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		forceHashError:     true,
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_hash_error"}`,
	},
	{
		body:               `name=John+Doe&account=jwt_generate_tokens_error&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_generate_tokens_error"}`,
	},
	{
		body:               `name=John+Doe&account=db_create_refresh_token_error&email=user%40example.com&password=Password1%21`,
		contentType:        "application/x-www-form-urlencoded",
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_generate_tokens_error"}`,
	},
}

func TestHandleRegister(t *testing.T) {
	var uri = "/api/v1/auth/register"
	originalGenerateFromPassword := generateFromPassword
	defer func() {
		generateFromPassword = originalGenerateFromPassword
	}()

	for _, tt := range registerTests {
		generateFromPassword = originalGenerateFromPassword
		if tt.forceHashError {
			generateFromPassword = func(password []byte, cost int) ([]byte, error) {
				return nil, errors.New("hash error")
			}
		}

		body := []byte(tt.body)
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", tt.contentType)

		rr := httptest.NewRecorder()

		engine.ServeHTTP(rr, req)

		if tt.expectedStatusCode != rr.Code {
			log.Println(body)
			log.Printf("error msg: %v", rr.Body.String())
			t.Errorf("received wrong status code. expected: %v, actual: %v", tt.expectedStatusCode, rr.Code)
		}

		if tt.expectedStatusCode == http.StatusCreated {
			var actual TokenResponse
			json.Unmarshal(rr.Body.Bytes(), &actual)

			var expected TokenResponse
			json.Unmarshal([]byte(tt.expectedResponse), &expected)

			if expected.AccessToken != actual.AccessToken {
				t.Errorf("received wrong accessToken. expected: %v, actual: %v", expected.AccessToken, actual.AccessToken)
			}
			if expected.RefreshToken != actual.RefreshToken {
				t.Errorf("received wrong refreshToken. expected: %v, actual: %v", expected.RefreshToken, actual.RefreshToken)
			}
			continue
		}

		var actual map[string]interface{}
		var expected map[string]interface{}

		err := json.Unmarshal(rr.Body.Bytes(), &actual)
		assert.NoError(t, err)

		err = json.Unmarshal([]byte(tt.expectedResponse), &expected)
		assert.NoError(t, err)

		assert.Equal(t, expected, actual)
	}
}

var refreshTests = []struct {
	body               string
	expectedStatusCode int
	expectedResponse   string
}{
	{
		body:               `{"refresh_token": "refreshToken"}`,
		expectedStatusCode: http.StatusOK,
		expectedResponse:   `{"access_token": "accessToken", "refresh_token": "refreshToken"}`,
	},
	{
		body:               ``,
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse:   `{"error": "invalid_request_body"}`,
	},
	{
		body:               `{"refresh_token": ""}`,
		expectedStatusCode: http.StatusBadRequest,
		expectedResponse: `{
			"error":"missing_required_fields",
			"details": {
				"refresh_token": "refresh_token_required"
			}
		}`,
	},
	{
		body:               `{"refresh_token": "jwt_expired_refresh_token"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "expired_token"}`,
	},
	{
		body:               `{"refresh_token": "jwt_invalid_refresh_token"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "invalid_token"}`,
	},
	{
		body:               `{"refresh_token": "jwt_parse_refresh_error"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "unauthorized"}`,
	},
	{
		body:               `{"refresh_token": "missing_refresh_token"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "invalid_token"}`,
	},
	{
		body:               `{"refresh_token": "db_get_refresh_token_error"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "unauthorized"}`,
	},
	{
		body:               `{"refresh_token": "revoked_refresh_token"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "invalid_token"}`,
	},
	{
		body:               `{"refresh_token": "expired_refresh_token"}`,
		expectedStatusCode: http.StatusUnauthorized,
		expectedResponse:   `{"error": "expired_token"}`,
	},
	{
		body:               `{"refresh_token": "jwt_generate_access_error_token"}`,
		expectedStatusCode: http.StatusInternalServerError,
		expectedResponse:   `{"error": "internal_generate_tokens_error"}`,
	},
}

func TestHandleRefresh(t *testing.T) {
	var uri = "/api/v1/auth/refresh"

	for _, tt := range refreshTests {
		body := []byte(tt.body)
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()

		engine.ServeHTTP(rr, req)

		if tt.expectedStatusCode != rr.Code {
			log.Println(body)
			log.Printf("error msg: %v", rr.Body.String())
			t.Errorf("received wrong status code. expected: %v, actual: %v", tt.expectedStatusCode, rr.Code)
		}

		if tt.expectedStatusCode == http.StatusOK {
			var actual TokenResponse
			json.Unmarshal(rr.Body.Bytes(), &actual)

			var expected TokenResponse
			json.Unmarshal([]byte(tt.expectedResponse), &expected)

			if expected.AccessToken != actual.AccessToken {
				t.Errorf("received wrong accessToken. expected: %v, actual: %v", expected.AccessToken, actual.AccessToken)
			}
			if expected.RefreshToken != actual.RefreshToken {
				t.Errorf("received wrong refreshToken. expected: %v, actual: %v", expected.RefreshToken, actual.RefreshToken)
			}
			continue
		}

		var actual map[string]interface{}
		var expected map[string]interface{}

		err := json.Unmarshal(rr.Body.Bytes(), &actual)
		assert.NoError(t, err)

		err = json.Unmarshal([]byte(tt.expectedResponse), &expected)
		assert.NoError(t, err)

		assert.Equal(t, expected, actual)
	}
}
