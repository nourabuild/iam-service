// Package webauthn provides WebAuthn/FIDO2 authentication support for passkeys.
// This is an experimental feature.
// See: https://github.com/go-webauthn/webauthn
package webauthn

import (
	"errors"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrRegistrationFailed = errors.New("registration failed")
	ErrLoginFailed        = errors.New("login failed")
)

type WebauthnService struct {
	wa      *webauthn.WebAuthn
	timeout time.Duration
}

func NewWebauthnService() *WebauthnService {
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}

	rpDisplayName := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if rpDisplayName == "" {
		rpDisplayName = "IAM Service"
	}

	rpOrigin := os.Getenv("WEBAUTHN_RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = "http://localhost:8080"
	}

	timeout := 60 * time.Second

	// Use default configuration that should always work
	config := &webauthn.Config{
		RPDisplayName: "IAM Service",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: timeout, TimeoutUVD: timeout, Enforce: true},
			Registration: webauthn.TimeoutConfig{Timeout: timeout, TimeoutUVD: timeout, Enforce: true},
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			UserVerification:        protocol.VerificationPreferred,
			ResidentKey:             protocol.ResidentKeyRequirementPreferred,
		},
	}

	// Try with environment variables first
	envConfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: timeout, TimeoutUVD: timeout, Enforce: true},
			Registration: webauthn.TimeoutConfig{Timeout: timeout, TimeoutUVD: timeout, Enforce: true},
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			UserVerification:        protocol.VerificationPreferred,
			ResidentKey:             protocol.ResidentKeyRequirementPreferred,
		},
	}

	wa, err := webauthn.New(envConfig)
	if err != nil {
		// Fall back to default config if environment config fails
		wa, err = webauthn.New(config)
		if err != nil {
			// This should never happen with default config, but handle gracefully
			return nil
		}
	}

	return &WebauthnService{wa: wa, timeout: timeout}
}

// BeginRegistration starts the WebAuthn registration process for a user.
func (s *WebauthnService) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	existingCreds := webauthn.Credentials(user.WebAuthnCredentials())
	defaultOpts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(existingCreds.CredentialDescriptors()),
	}

	creation, session, err := s.wa.BeginRegistration(user, append(defaultOpts, opts...)...)
	if err != nil {
		return nil, nil, errors.Join(ErrRegistrationFailed, err)
	}
	return creation, session, nil
}

func (s *WebauthnService) FinishRegistration(user webauthn.User, session *webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	credential, err := s.wa.CreateCredential(user, *session, response)
	if err != nil {
		return nil, errors.Join(ErrRegistrationFailed, err)
	}
	return credential, nil
}

// BeginLogin starts the WebAuthn login process for a known user (MFA).
func (s *WebauthnService) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	assertion, session, err := s.wa.BeginLogin(user, opts...)
	if err != nil {
		return nil, nil, errors.Join(ErrLoginFailed, err)
	}
	return assertion, session, nil
}

func (s *WebauthnService) FinishLogin(user webauthn.User, session *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	credential, err := s.wa.ValidateLogin(user, *session, response)
	if err != nil {
		return nil, errors.Join(ErrLoginFailed, err)
	}
	return credential, nil
}

// BeginPasskeyLogin starts the passwordless login process where the user is discovered from their credential.
func (s *WebauthnService) BeginPasskeyLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(opts...)
	if err != nil {
		return nil, nil, errors.Join(ErrLoginFailed, err)
	}
	return assertion, session, nil
}

func (s *WebauthnService) FinishPasskeyLogin(handler webauthn.DiscoverableUserHandler, session *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (webauthn.User, *webauthn.Credential, error) {
	user, credential, err := s.wa.ValidatePasskeyLogin(handler, *session, response)
	if err != nil {
		return nil, nil, errors.Join(ErrLoginFailed, err)
	}
	return user, credential, nil
}

// ParseRegistrationResponse parses a WebAuthn registration response from bytes.
func ParseRegistrationResponse(body []byte) (*protocol.ParsedCredentialCreationData, error) {
	return protocol.ParseCredentialCreationResponseBytes(body)
}

func ParseLoginResponse(body []byte) (*protocol.ParsedCredentialAssertionData, error) {
	return protocol.ParseCredentialRequestResponseBytes(body)
}
