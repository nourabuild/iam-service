package app

import (
	"net/mail"
	"strings"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8
	minAccountLength  = 6
	bcryptCost        = bcrypt.DefaultCost
)

type passwordComplexity struct {
	hasUpper   bool
	hasNumber  bool
	hasSpecial bool
}

func validateRegisterInput(req models.NewUser) (string, map[string]string) {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.Name) == "" {
		validationErrors["name"] = "name_required"
	}
	if strings.TrimSpace(req.Account) == "" {
		validationErrors["account"] = "account_required"
	}
	if strings.TrimSpace(req.Email) == "" {
		validationErrors["email"] = "email_required"
	}
	if len(req.Password) == 0 {
		validationErrors["password"] = "password_required"
	}

	if len(validationErrors) > 0 {
		return ErrMissingFields, validationErrors
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		validationErrors["email"] = "invalid_email_format"
	}

	if len(req.Account) < minAccountLength {
		validationErrors["account"] = "account_too_short"
	}

	var complexity passwordComplexity
	if len(req.Password) < minPasswordLength {
		validationErrors["password"] = "password_too_short"
	} else {
		complexity = passwordComplexityFlags(req.Password)
		if !complexity.hasUpper {
			validationErrors["password"] = "password_no_uppercase"
		} else if !complexity.hasNumber {
			validationErrors["password"] = "password_no_number"
		} else if !complexity.hasSpecial {
			validationErrors["password"] = "password_no_special_char"
		}
	}

	if len(validationErrors) == 0 {
		return "", nil
	}

	return primaryRegisterError(validationErrors, req.Password, complexity), validationErrors
}

func validateLoginInput(req LoginRequest) map[string]string {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.Account) == "" {
		validationErrors["account"] = "account_required"
	}
	if req.Password == "" {
		validationErrors["password"] = "password_required"
	}

	if len(validationErrors) == 0 {
		return nil
	}

	return validationErrors
}

func validateRefreshInput(req RefreshRequest) map[string]string {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.RefreshToken) == "" {
		validationErrors["refresh_token"] = "refresh_token_required"
	}

	if len(validationErrors) == 0 {
		return nil
	}

	return validationErrors
}

func passwordComplexityFlags(password []byte) passwordComplexity {
	var complexity passwordComplexity
	for _, char := range string(password) {
		switch {
		case char >= 'A' && char <= 'Z':
			complexity.hasUpper = true
		case char >= '0' && char <= '9':
			complexity.hasNumber = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			complexity.hasSpecial = true
		}
	}

	return complexity
}

func primaryRegisterError(details map[string]string, password []byte, complexity passwordComplexity) string {
	errCode := ErrInvalidEmail
	if _, hasAccountErr := details["account"]; hasAccountErr {
		errCode = ErrAccountTooShort
	}
	if _, hasPasswordErr := details["password"]; hasPasswordErr {
		if len(password) < minPasswordLength {
			errCode = ErrPasswordTooShort
		} else if !complexity.hasUpper {
			errCode = ErrPasswordNoUppercase
		} else if !complexity.hasNumber {
			errCode = ErrPasswordNoNumber
		} else if !complexity.hasSpecial {
			errCode = ErrPasswordNoSpecialChar
		}
	}

	return errCode
}
