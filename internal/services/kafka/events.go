package kafka

import "time"

const (
	TopicUserCreated = "iam.user.created"
	TopicUserUpdated = "iam.user.updated"
)

type UserCreatedEvent struct {
	EventType  string    `json:"event_type"`
	UserID     string    `json:"user_id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	Account    string    `json:"account"`
	IsAdmin    bool      `json:"is_admin"`
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
	OccurredAt    time.Time `json:"occurred_at"`
}
