package jwt

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	testIssuer        = "test-issuer"
	testAccessSecret  = "test-access-secret"
	testRefreshSecret = "test-refresh-secret"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("JWT_ISSUER", testIssuer)
	_ = os.Setenv("JWT_ACCESS_TOKEN_SECRET", testAccessSecret)
	_ = os.Setenv("JWT_REFRESH_TOKEN_SECRET", testRefreshSecret)

	code := m.Run()
	os.Exit(code)
}

func TestNewTokenService(t *testing.T) {
	srv := NewTokenService()
	if srv == nil {
		t.Fatal("NewTokenService() returned nil")
	}
	if srv.Issuer != testIssuer {
		t.Fatalf("expected issuer %q, got %q", testIssuer, srv.Issuer)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewTokenService()
		access, err := srv.GenerateAccessToken(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateAccessToken returned error: %v", err)
		}
		if access == "" {
			t.Fatal("expected non-empty access token")
		}
	})

	t.Run("missing access secret", func(t *testing.T) {
		srv := NewTokenService()
		srv.AccessTokenSecretKey = nil

		_, err := srv.GenerateAccessToken(context.Background(), "user-123", true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "creating access token") {
			t.Fatalf("expected wrapped create error, got %v", err)
		}
	})
}

func TestGenerateTokens(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewTokenService()
		access, refresh, err := srv.GenerateTokens(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateTokens returned error: %v", err)
		}
		if access == "" {
			t.Fatal("expected non-empty access token")
		}
		if refresh == "" {
			t.Fatal("expected non-empty refresh token")
		}
	})

	t.Run("missing access secret", func(t *testing.T) {
		srv := NewTokenService()
		srv.AccessTokenSecretKey = nil

		_, _, err := srv.GenerateTokens(context.Background(), "user-123", true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "creating access token") {
			t.Fatalf("expected access token create error, got %v", err)
		}
	})

	t.Run("missing refresh secret", func(t *testing.T) {
		srv := NewTokenService()
		srv.RefreshTokenSecretKey = nil

		_, _, err := srv.GenerateTokens(context.Background(), "user-123", true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "creating refresh token") {
			t.Fatalf("expected refresh token create error, got %v", err)
		}
	})
}

func TestParseAccessToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewTokenService()
		access, err := srv.GenerateAccessToken(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateAccessToken returned error: %v", err)
		}

		claims, err := srv.ParseAccessToken(context.Background(), access)
		if err != nil {
			t.Fatalf("ParseAccessToken returned error: %v", err)
		}
		if claims.Subject != "user-123" {
			t.Fatalf("expected subject user-123, got %q", claims.Subject)
		}
		if !claims.IsAdmin {
			t.Fatal("expected isAdmin=true")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		srv := NewTokenService()

		_, err := srv.ParseAccessToken(context.Background(), "")
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("expected ErrTokenNotFound, got %v", err)
		}
	})
}

func TestParseRefreshToken(t *testing.T) {
	srv := NewTokenService()
	_, refresh, err := srv.GenerateTokens(context.Background(), "user-123", true)
	if err != nil {
		t.Fatalf("GenerateTokens returned error: %v", err)
	}

	claims, err := srv.ParseRefreshToken(context.Background(), refresh)
	if err != nil {
		t.Fatalf("ParseRefreshToken returned error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("expected subject user-123, got %q", claims.Subject)
	}
	if !claims.IsAdmin {
		t.Fatal("expected isAdmin=true")
	}
}

func TestRefreshTokens(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewTokenService()
		_, refresh, err := srv.GenerateTokens(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateTokens returned error: %v", err)
		}

		newAccess, newRefresh, err := srv.RefreshTokens(context.Background(), refresh)
		if err != nil {
			t.Fatalf("RefreshTokens returned error: %v", err)
		}
		if newAccess == "" {
			t.Fatal("expected non-empty new access token")
		}
		if newRefresh != refresh {
			t.Fatal("expected refresh token to stay the same")
		}
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		srv := NewTokenService()

		_, _, err := srv.RefreshTokens(context.Background(), "invalid-refresh-token")
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("missing access secret", func(t *testing.T) {
		srv := NewTokenService()
		_, refresh, err := srv.GenerateTokens(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateTokens returned error: %v", err)
		}

		srv.AccessTokenSecretKey = nil
		_, _, err = srv.RefreshTokens(context.Background(), refresh)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "creating access token") {
			t.Fatalf("expected wrapped create error, got %v", err)
		}
	})
}

func TestValidateAccessToken(t *testing.T) {
	srv := NewTokenService()
	access, err := srv.GenerateAccessToken(context.Background(), "user-123", true)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	if err := srv.ValidateAccessToken(context.Background(), access); err != nil {
		t.Fatalf("ValidateAccessToken returned error: %v", err)
	}
}

func TestGetSubjectFromToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewTokenService()
		access, err := srv.GenerateAccessToken(context.Background(), "user-123", true)
		if err != nil {
			t.Fatalf("GenerateAccessToken returned error: %v", err)
		}

		subject, err := srv.GetSubjectFromToken(context.Background(), access)
		if err != nil {
			t.Fatalf("GetSubjectFromToken returned error: %v", err)
		}
		if subject != "user-123" {
			t.Fatalf("expected subject user-123, got %q", subject)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		srv := NewTokenService()

		_, err := srv.GetSubjectFromToken(context.Background(), "not-a-jwt")
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})
}
