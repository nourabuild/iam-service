package app

import "net/http"

const (
	ErrUnmarshal             = "invalid_request_body"
	ErrMissingFields         = "missing_required_fields"
	ErrInvalidEmail          = "invalid_email"
	ErrPasswordTooShort      = "password_too_short"
	ErrPasswordNoUppercase   = "password_must_contain_uppercase"
	ErrPasswordNoNumber      = "password_must_contain_number"
	ErrPasswordNoSpecialChar = "password_must_contain_special_character"
	ErrAccountTooShort       = "account_too_short"
	ErrUserExists            = "user_already_exists"
	ErrInvalidCredentials    = "invalid_credentials"
	ErrUnauthorized          = "unauthorized"
	ErrForbidden             = "forbidden"
	ErrHashPassword          = "internal_hash_error"
	ErrCreateUser            = "internal_create_user_error"
	ErrProcessLogin          = "internal_login_error"
	ErrRetrieveUsers         = "internal_retrieve_users_error"
	ErrGenerateTokens        = "internal_generate_tokens_error"
	ErrExpiredToken          = "expired_token"
	ErrInvalidToken          = "invalid_token"
	ErrMissingAuthHeader     = "missing_authorization_header"
	ErrInvalidAuthHeader     = "invalid_authorization_header"
	ErrUserNotFound          = "user_not_found"
	ErrVerifyUser            = "internal_verify_user_error"
	ErrInvalidUserID         = "invalid_user_id"
	ErrPromoteUser           = "internal_promote_user_error"
)

var errorStatusMap = map[string]int{
	ErrUnmarshal:             http.StatusBadRequest,
	ErrMissingFields:         http.StatusBadRequest,
	ErrInvalidEmail:          http.StatusBadRequest,
	ErrPasswordTooShort:      http.StatusBadRequest,
	ErrPasswordNoUppercase:   http.StatusBadRequest,
	ErrPasswordNoNumber:      http.StatusBadRequest,
	ErrPasswordNoSpecialChar: http.StatusBadRequest,
	ErrAccountTooShort:       http.StatusBadRequest,
	ErrUserExists:            http.StatusConflict,
	ErrInvalidCredentials:    http.StatusUnauthorized,
	ErrUnauthorized:          http.StatusUnauthorized,
	ErrForbidden:             http.StatusForbidden,
	ErrHashPassword:          http.StatusInternalServerError,
	ErrCreateUser:            http.StatusInternalServerError,
	ErrProcessLogin:          http.StatusInternalServerError,
	ErrRetrieveUsers:         http.StatusInternalServerError,
	ErrGenerateTokens:        http.StatusInternalServerError,
	ErrExpiredToken:          http.StatusUnauthorized,
	ErrInvalidToken:          http.StatusUnauthorized,
	ErrMissingAuthHeader:     http.StatusUnauthorized,
	ErrInvalidAuthHeader:     http.StatusUnauthorized,
	ErrUserNotFound:          http.StatusUnauthorized,
	ErrVerifyUser:            http.StatusInternalServerError,
	ErrInvalidUserID:         http.StatusBadRequest,
	ErrPromoteUser:           http.StatusInternalServerError,
}

func statusForError(code string) int {
	if status, ok := errorStatusMap[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}
