package server

import (
	"net/http"
)

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
