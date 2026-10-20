// Package models defines data models for the IAM service.
package models

import "time"

const (
	// TopicUserCreated carries newly registered users.
	TopicUserCreated = "iam.user.created"
	// TopicUserUpdated carries user profile and role changes.
	TopicUserUpdated = "iam.user.updated"
	// HeaderCorrelationID links an event to its originating request.
	HeaderCorrelationID = "correlation_id"
)

// Role identifies a user's authorization role.
type Role string

const (
	// RoleUser grants standard user permissions.
	RoleUser Role = "user"
	// RoleAdmin grants administrative permissions.
	RoleAdmin Role = "admin"
)

// Valid reports whether r is a recognized role.
func (r Role) Valid() bool {
	return r == RoleUser || r == RoleAdmin
}

// Principal identifies an authenticated user and their authorization role.
type Principal struct {
	ID   string `json:"id"`
	Role Role   `json:"role"`
}

// IsAdmin reports whether p has the administrator role.
func (p Principal) IsAdmin() bool {
	return p.Role == RoleAdmin
}

// RefreshToken represents a stored refresh token for a user.
type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// NewRefreshToken contains the values required to store a refresh token.
type NewRefreshToken struct {
	UserID    string
	Token     []byte
	ExpiresAt time.Time
}

// User represents an IAM user.
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
	Role          Role      `json:"role"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// NewUser contains the values required to create a user.
type NewUser struct {
	Name     string
	Account  string
	Email    string
	Password []byte
}

// UpdateUser contains mutable user profile fields.
type UpdateUser struct {
	Name    string  `json:"name"`
	Account string  `json:"account"`
	Bio     *string `json:"bio"`
	DOB     *string `json:"dob"`
	City    *string `json:"city"`
	Phone   *string `json:"phone"`
}

// PasswordResetToken represents a stored password-reset token for a user.
type PasswordResetToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// NewPasswordResetToken contains the values required to store a password-reset token.
type NewPasswordResetToken struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

// OutboxMessage is an event to be written to auth.outbox in the same
// transaction as the mutation it announces. Payload is JSON-marshaled.
type OutboxMessage struct {
	Topic   string
	Key     string
	Payload any
	Headers map[string]string
}

// OutboxRow is a pending event read back from auth.outbox by the relay.
type OutboxRow struct {
	ID        int64
	Topic     string
	Key       string
	Payload   []byte
	Headers   map[string]string
	CreatedAt time.Time
}

// Liveness describes the process state returned by the liveness endpoint.
type Liveness struct {
	Status     string `json:"status"`
	Host       string `json:"host"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}

// UserCreatedEvent describes a newly created user for event consumers.
type UserCreatedEvent struct {
	EventType  string    `json:"event_type"`
	UserID     string    `json:"user_id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	Account    string    `json:"account"`
	IsAdmin    bool      `json:"is_admin"`
	Role       Role      `json:"role"`
	OccurredAt time.Time `json:"occurred_at"`
}

// UserUpdatedEvent describes updated user state for event consumers.
type UserUpdatedEvent struct {
	EventType     string    `json:"event_type"`
	UserID        string    `json:"user_id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	Account       string    `json:"account"`
	Bio           *string   `json:"bio,omitempty"`
	DOB           *string   `json:"dob,omitempty"`
	City          *string   `json:"city,omitempty"`
	Phone         *string   `json:"phone,omitempty"`
	AvatarPhotoID *int      `json:"avatar_photo_id,omitempty"`
	IsAdmin       bool      `json:"is_admin"`
	Role          Role      `json:"role"`
	OccurredAt    time.Time `json:"occurred_at"`
}
