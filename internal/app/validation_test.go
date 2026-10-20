package app

import (
	"strings"
	"testing"
)

func TestValidateRegisterInputRejectsPasswordAboveBcryptLimit(t *testing.T) {
	password := []byte(strings.Repeat("A", maxPasswordLength+1))
	errCode, details := validateRegisterInput(registerRequest{
		Name:            "Ada Lovelace",
		Account:         "adalovelace",
		Email:           "ada@example.com",
		Password:        password,
		PasswordConfirm: append([]byte(nil), password...),
	})

	if errCode != "password_too_long" {
		t.Fatalf("error = %q, want password_too_long", errCode)
	}
	if got := details["password"]; got != "password_too_long" {
		t.Fatalf("password detail = %q, want password_too_long", got)
	}
}
