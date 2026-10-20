// Package errs defines errors that can be safely mapped to HTTP responses.
package errs

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
)

// Error is an application error that can be mapped safely to an HTTP response.
type Error struct {
	Key    string            `json:"key"`
	Status int               `json:"-"`
	Fields map[string]string `json:"fields,omitempty"`
	Err    error             `json:"-"`
}

// Error returns the public error key followed by the wrapped error, if any.
func (e *Error) Error() string {
	if e.Err == nil {
		return e.Key
	}
	return fmt.Sprintf("%s: %v", e.Key, e.Err)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// New creates an application error without an underlying cause.
func New(status int, key string) *Error {
	return &Error{Status: status, Key: key}
}

// Wrap creates an application error that wraps err.
func Wrap(err error, status int, key string) *Error {
	return &Error{Status: status, Key: key, Err: err}
}

// WithFields returns a copy of err containing the supplied response fields.
func WithFields(err *Error, fields map[string]string) *Error {
	if err == nil {
		return nil
	}
	clone := *err
	if len(fields) == 0 {
		clone.Fields = nil
		return &clone
	}
	clone.Fields = make(map[string]string, len(fields))
	maps.Copy(clone.Fields, fields)
	return &clone
}

// From extracts an application Error from err's chain.
func From(err error) (*Error, bool) {
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

var (
	// ErrBadRequest represents an invalid client request.
	ErrBadRequest = New(http.StatusBadRequest, "bad_request")
	// ErrUnauthorized represents a missing or invalid identity.
	ErrUnauthorized = New(http.StatusUnauthorized, "unauthorized")
	// ErrForbidden represents an authenticated caller without permission.
	ErrForbidden = New(http.StatusForbidden, "forbidden")
	// ErrNotFound represents a requested resource that does not exist.
	ErrNotFound = New(http.StatusNotFound, "not_found")
	// ErrConflict represents a request that conflicts with existing state.
	ErrConflict = New(http.StatusConflict, "conflict")
	// ErrInternal represents an unexpected server failure.
	ErrInternal = New(http.StatusInternalServerError, "internal_error")
)
