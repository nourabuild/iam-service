package app

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var loginTests = []struct {
	body               string
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
}

var registerTests = []struct {
	body               string
	contentType        string
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
}

func TestHandleRegister(t *testing.T) {
	var uri = "/api/v1/auth/register"

	for _, tt := range registerTests {
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
	}
}

func TestHandleLogin(t *testing.T) {
	var uri = "/api/v1/auth/login"

	for _, tt := range loginTests {

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
