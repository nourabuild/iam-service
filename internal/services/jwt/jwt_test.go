package jwt

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

const (
	testAccessSecret  = "test-access-secret-0123456789abcdef"
	testRefreshSecret = "test-refresh-secret-0123456789abcdef"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("JWT_ACCESS_TOKEN_SECRET", testAccessSecret)
	_ = os.Setenv("JWT_REFRESH_TOKEN_SECRET", testRefreshSecret)
	os.Exit(m.Run())
}

func mustService(t *testing.T) *TokenService {
	t.Helper()
	svc, err := NewTokenService()
	if err != nil {
		t.Fatalf("NewTokenService() returned error: %v", err)
	}
	return svc
}

func TestNewTokenService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := mustService(t)
		if svc.Issuer != issuer {
			t.Fatalf("expected issuer %q, got %q", issuer, svc.Issuer)
		}
	})

	t.Run("missing access secret", func(t *testing.T) {
		t.Setenv("JWT_ACCESS_TOKEN_SECRET", "")
		if _, err := NewTokenService(); err == nil {
			t.Fatal("expected error for missing access secret, got nil")
		}
	})

	t.Run("missing refresh secret", func(t *testing.T) {
		t.Setenv("JWT_REFRESH_TOKEN_SECRET", "")
		if _, err := NewTokenService(); err == nil {
			t.Fatal("expected error for missing refresh secret, got nil")
		}
	})

	t.Run("short secret rejected", func(t *testing.T) {
		t.Setenv("JWT_ACCESS_TOKEN_SECRET", "too-short")
		if _, err := NewTokenService(); err == nil {
			t.Fatal("expected error for short secret, got nil")
		}
	})

	t.Run("whitespace-only secret rejected", func(t *testing.T) {
		t.Setenv("JWT_ACCESS_TOKEN_SECRET", "                                        ")
		if _, err := NewTokenService(); err == nil {
			t.Fatal("expected error for whitespace secret, got nil")
		}
	})
}

func TestGenerateAndParseRoundTrip(t *testing.T) {
	svc := mustService(t)
	ctx := context.Background()

	access, refresh, err := svc.GenerateTokens(ctx, "user-123", true)
	if err != nil {
		t.Fatalf("GenerateTokens returned error: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty token pair")
	}

	claims, err := svc.ParseAccessToken(ctx, access)
	if err != nil {
		t.Fatalf("ParseAccessToken returned error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("expected subject user-123, got %q", claims.Subject)
	}
	if !claims.IsAdmin {
		t.Error("expected is_admin claim to be true")
	}
	if claims.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, claims.Issuer)
	}

	refreshClaims, err := svc.ParseRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatalf("ParseRefreshToken returned error: %v", err)
	}
	if refreshClaims.Subject != "user-123" {
		t.Errorf("expected refresh subject user-123, got %q", refreshClaims.Subject)
	}
}

// TestTokensAreUnique is the regression test for same-second token collisions:
// without a random jti, two tokens for the same subject issued within one
// second are byte-identical, which silently breaks refresh-token rotation and
// reuse detection.
func TestTokensAreUnique(t *testing.T) {
	svc := mustService(t)
	ctx := context.Background()

	access1, refresh1, err := svc.GenerateTokens(ctx, "user-123", false)
	if err != nil {
		t.Fatalf("GenerateTokens returned error: %v", err)
	}
	access2, refresh2, err := svc.GenerateTokens(ctx, "user-123", false)
	if err != nil {
		t.Fatalf("GenerateTokens returned error: %v", err)
	}

	if access1 == access2 {
		t.Error("two access tokens issued back-to-back are identical; jti missing?")
	}
	if refresh1 == refresh2 {
		t.Error("two refresh tokens issued back-to-back are identical; jti missing?")
	}
}

func TestParseExpiredToken(t *testing.T) {
	svc := mustService(t)
	svc.AccessTokenExpiry = -time.Minute

	token, err := svc.GenerateAccessToken(context.Background(), "user-123", false)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	_, err = svc.ParseAccessToken(context.Background(), token)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestCrossSecretRejection(t *testing.T) {
	svc := mustService(t)
	ctx := context.Background()

	access, refresh, err := svc.GenerateTokens(ctx, "user-123", false)
	if err != nil {
		t.Fatalf("GenerateTokens returned error: %v", err)
	}

	// A refresh token must never be accepted as an access token, and vice
	// versa: they are signed with different secrets.
	if _, err := svc.ParseAccessToken(ctx, refresh); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("refresh token accepted as access token; want ErrInvalidToken, got %v", err)
	}
	if _, err := svc.ParseRefreshToken(ctx, access); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("access token accepted as refresh token; want ErrInvalidToken, got %v", err)
	}
}

func TestWrongSignatureRejected(t *testing.T) {
	svc := mustService(t)

	other := *svc
	other.AccessTokenSecretKey = []byte("a-completely-different-secret-key-value")

	token, err := other.GenerateAccessToken(context.Background(), "user-123", false)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	if _, err := svc.ParseAccessToken(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for wrong signature, got %v", err)
	}
}

func TestAlgNoneRejected(t *testing.T) {
	svc := mustService(t)

	claims := Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    issuer,
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned := gojwt.NewWithClaims(gojwt.SigningMethodNone, claims)
	token, err := unsigned.SignedString(gojwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing alg=none token: %v", err)
	}

	if _, err := svc.ParseAccessToken(context.Background(), token); err == nil {
		t.Fatal("alg=none token was accepted; expected rejection")
	}
}

func TestIssuerMismatchRejected(t *testing.T) {
	svc := mustService(t)

	other := *svc
	other.Issuer = "some-other-service"

	token, err := other.GenerateAccessToken(context.Background(), "user-123", false)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	if _, err := svc.ParseAccessToken(context.Background(), token); err == nil {
		t.Fatal("token with wrong issuer was accepted; expected rejection")
	}
}

func TestParseInvalidInput(t *testing.T) {
	svc := mustService(t)
	ctx := context.Background()

	if _, err := svc.ParseAccessToken(ctx, ""); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound for empty token, got %v", err)
	}
	if _, err := svc.ParseAccessToken(ctx, "not-a-jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for malformed token, got %v", err)
	}
}

func TestGenerateWithEmptySecret(t *testing.T) {
	svc := mustService(t)
	svc.AccessTokenSecretKey = nil

	if _, err := svc.GenerateAccessToken(context.Background(), "user-123", false); err == nil {
		t.Fatal("expected error generating token with empty secret, got nil")
	}
}
