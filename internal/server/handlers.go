package server

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/errs"
)

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Account   string    `json:"account"`
	Email     string    `json:"email"`
	Password  []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NewUser struct {
	Name            string `json:"name" validate:"required,min=3"`
	Account         string `json:"account" validate:"required,min=6"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	PasswordConfirm string `json:"password_confirm" validate:"required,eqfield=Password"`
}

func (s *Server) healthDbHandler(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) healthApiHandler(w http.ResponseWriter, r *http.Request) {
	host, err := os.Hostname()
	if err != nil {
		host = "unavailable"
	}

	info := map[string]string{
		"status":     "up",
		"host":       host,
		"GOMAXPROCS": string(rune(runtime.GOMAXPROCS(0))),
	}

	jsonResp, err := json.Marshal(info)
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement authentication logic
	// - Validate credentials against database
	// - Generate access token and refresh token
	// - Return tokens to client

	resp := map[string]string{
		"message":       "Login successful",
		"access_token":  "placeholder_access_token",
		"refresh_token": "placeholder_refresh_token",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB max
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	newUser := NewUser{
		Name:            r.FormValue("name"),
		Account:         r.FormValue("account"),
		Email:           r.FormValue("email"),
		Password:        r.FormValue("password"),
		PasswordConfirm: r.FormValue("password_confirm"),
	}

	// TODO: Implement registration logic
	// - Validate newUser using validator (validate tags)
	// - Check password and password_confirm match
	// - Check if user already exists
	// - Hash password
	// - Create user in database
	// - Generate access token and refresh token
	// - Return tokens to client

	_ = newUser

	resp := map[string]string{
		"message":       "Registration successful",
		"access_token":  "placeholder_access_token",
		"refresh_token": "placeholder_refresh_token",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var tokenReq struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&tokenReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: Implement token refresh logic
	// - Validate refresh token
	// - Check if token is expired or revoked
	// - Generate new access token
	// - Optionally rotate refresh token
	// - Return new tokens to client

	resp := map[string]string{
		"message":       "Token refreshed successfully",
		"access_token":  "new_placeholder_access_token",
		"refresh_token": "new_placeholder_refresh_token",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
