package app

import "time"

type LoginRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Account   string    `json:"account"`
	Email     string    `json:"email"`
	Bio       *string   `json:"bio,omitempty"`
	DOB       *string   `json:"dob,omitempty"`
	City      *string   `json:"city,omitempty"`
	Phone     *string   `json:"phone,omitempty"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

type LivenessResponse struct {
	Status     string `json:"status"`
	Host       string `json:"host"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}
