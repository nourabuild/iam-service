// Package models defines data models for the IAM service.
package models

import "time"

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Account   string    `json:"account"`
	Email     string    `json:"email"`
	Password  []byte    `json:"-"`
	Bio       *string   `json:"bio,omitempty"`
	DOB       *string   `json:"dob,omitempty"`
	City      *string   `json:"city,omitempty"`
	Phone     *string   `json:"phone,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NewUser struct {
	Name     string `json:"name"`
	Account  string `json:"account"`
	Email    string `json:"email"`
	Password []byte `json:"-"`
}
