package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// newAdminEngine wires AuthorizeAdmin behind a setup middleware that seeds the
// context the way Authenticate would.
func newAdminEngine(seed func(c *gin.Context)) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin",
		func(c *gin.Context) { seed(c); c.Next() },
		AuthorizeAdmin(),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)
	return r
}

func TestAuthorizeAdmin(t *testing.T) {
	tests := []struct {
		name           string
		seed           func(c *gin.Context)
		expectedStatus int
	}{
		{
			name:           "no is_admin in context",
			seed:           func(c *gin.Context) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "is_admin wrong type",
			seed:           func(c *gin.Context) { c.Set(IsAdminKey, "true") },
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "non-admin user",
			seed:           func(c *gin.Context) { c.Set(IsAdminKey, false) },
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "admin user",
			seed:           func(c *gin.Context) { c.Set(IsAdminKey, true) },
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newAdminEngine(tt.seed)

			req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}
