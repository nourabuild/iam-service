package server

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/nourabuild/iam-service/internal/sdk/errs"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

type MidFunc func(http.Handler) http.Handler

// WrapMiddleware wraps an http.Handler with the provided middlewares.
func WrapMiddleware(h http.Handler, middlewares ...MidFunc) http.Handler {
	// Apply middlewares in reverse order
	for i := len(middlewares) - 1; i >= 0; i-- {
		if middlewares[i] != nil {
			h = middlewares[i](h)
		}
	}
	return h
}

// --------------------------------------
// CORS
// --------------------------------------

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Replace "*" with specific origins if needed
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "false") // Set to "true" if credentials are required

		// Handle preflight OPTIONS requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Proceed with the next handler
		next.ServeHTTP(w, r)
	})
}

// --------------------------------------
// Logging
// --------------------------------------

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request details
		ip := r.RemoteAddr
		proto := r.Proto
		method := r.Method
		uri := r.URL.RequestURI()

		log.Printf("IP: %s, Protocol: %s, Method: %s, URI: %s", ip, proto, method, uri)

		next.ServeHTTP(w, r)
	})
}

// --------------------------------------
// Authentication
// --------------------------------------

// Context key for user ID
type claimsContextKey string

const (
	bearerPrefix = "Bearer "
	claimsKey    = claimsContextKey("claims")
)

// authMiddleware validates JWT token and adds claims to context
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			appErr := errs.Newf(errs.Unauthenticated, "authorization header is required")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(appErr.HTTPStatus())
			w.Write([]byte(`{"code":"unauthenticated","message":"authorization header is required"}`))
			return
		}

		// Check Bearer prefix
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			appErr := errs.Newf(errs.Unauthenticated, "invalid authorization header format")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(appErr.HTTPStatus())
			w.Write([]byte(`{"code":"unauthenticated","message":"invalid authorization header format"}`))
			return
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)

		// Parse and validate token
		tokenService := jwt.NewTokenService()
		claims, err := tokenService.ParseAccessToken(tokenString)
		if err != nil {
			appErr := errs.Newf(errs.Unauthenticated, "invalid or expired token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(appErr.HTTPStatus())
			w.Write([]byte(`{"code":"unauthenticated","message":"invalid or expired token"}`))
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaimsFromContext extracts claims from request context
func GetClaimsFromContext(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*jwt.Claims)
	return claims, ok
}

// SetClaimsContext sets claims in context (for testing purposes)
func SetClaimsContext(ctx context.Context, claims *jwt.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}
