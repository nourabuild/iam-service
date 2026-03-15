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
