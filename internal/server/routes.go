package server

import (
	"net/http"
)

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	s.registerHealthRoutes(mux)
	s.registerAuthRoutes(mux)

	return WrapMiddleware(mux,
		s.corsMiddleware,
		s.loggingMiddleware,
	)
}

func (s *Server) registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health/readiness", s.healthDbHandler)
	mux.HandleFunc("GET /api/v1/health/liveness", s.healthApiHandler)
}

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.loginHandler)
	mux.HandleFunc("POST /api/v1/auth/register", s.registerHandler)
	mux.HandleFunc("POST /api/v1/auth/refresh-token", s.refreshTokenHandler)
}
