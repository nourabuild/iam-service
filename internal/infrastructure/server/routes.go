package server

import (
	"encoding/json"
	"log"
	"net/http"
)

// Middleware

// MidFunc is a function that wraps an http.Handler.
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

// Routes

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("GET /", s.HelloWorldHandler)
	mux.HandleFunc("GET /health", s.healthHandler)

	// Apply middleware chain (order: cors -> logging -> handler)
	return WrapMiddleware(mux,
		s.corsMiddleware,
		s.loggingMiddleware,
	)
}

// Handlers

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"message": "Hello World"}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(s.sqldb.Health())
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
