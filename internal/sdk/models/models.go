// Package models defines data models for the IAM service.
package models

import "time"

// RefreshToken represents a refresh token for a user
type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type NewRefreshToken struct {
	UserID    string
	Token     []byte
	ExpiresAt time.Time
}

// User represents a user in the system
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Account       string    `json:"account"`
	Email         string    `json:"email"`
	Password      []byte    `json:"-"`
	Bio           *string   `json:"bio,omitempty"`
	DOB           *string   `json:"dob,omitempty"`
	City          *string   `json:"city,omitempty"`
	Phone         *string   `json:"phone,omitempty"`
	AvatarPhotoID *int      `json:"avatar_photo_id,omitempty"`
	IsAdmin       bool      `json:"is_admin"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type NewUser struct {
	Name            string `json:"name"`
	Account         string `json:"account"`
	Email           string `json:"email"`
	Password        []byte `json:"password"`
	PasswordConfirm []byte `json:"password_confirm"`
}

// PasswordResetToken represents a password reset token for a user
type PasswordResetToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type NewPasswordResetToken struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}
