package errs

import (
	"errors"
	"fmt"
	"net/http"
)

type Error struct {
	Key    string            `json:"key"`
	Status int               `json:"-"`
	Fields map[string]string `json:"fields,omitempty"`
	Err    error             `json:"-"`
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Key
	}
	return fmt.Sprintf("%s: %v", e.Key, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func New(status int, key string) *Error {
	return &Error{Status: status, Key: key}
}

func Wrap(err error, status int, key string) *Error {
	return &Error{Status: status, Key: key, Err: err}
}

func WithFields(err *Error, fields map[string]string) *Error {
	err.Fields = fields
	return err
}

func From(err error) (*Error, bool) {
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

var (
	ErrBadRequest   = New(http.StatusBadRequest, "bad_request")
	ErrUnauthorized = New(http.StatusUnauthorized, "unauthorized")
	ErrForbidden    = New(http.StatusForbidden, "forbidden")
	ErrNotFound     = New(http.StatusNotFound, "not_found")
	ErrConflict     = New(http.StatusConflict, "conflict")
	ErrInternal     = New(http.StatusInternalServerError, "internal_error")
)
