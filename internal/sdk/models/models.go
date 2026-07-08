// Package models defines data models for the IAM service.
package models

import "time"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

func (r Role) Valid() bool {
	return r == RoleUser || r == RoleAdmin
}

type Principal struct {
	ID   string `json:"id"`
	Role Role   `json:"role"`
}

func (p Principal) IsAdmin() bool {
	return p.Role == RoleAdmin
}

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
	Role          Role      `json:"role"`
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

type UpdateUser struct {
	Name    string  `json:"name"`
	Account string  `json:"account"`
	Bio     *string `json:"bio"`
	DOB     *string `json:"dob"`
	City    *string `json:"city"`
	Phone   *string `json:"phone"`
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

type Liveness struct {
	Status     string `json:"status"`
	Host       string `json:"host"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}

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
