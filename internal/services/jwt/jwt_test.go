package jwt

import (
	"bytes"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

const (
	testSecret = "test-access-secret-0123456789abcdef"
	testIssuer = "noura-iam-service-test"
)

func mustService(t *testing.T) *TokenService {
	t.Helper()

	return NewTokenService(config.AuthConfig{
		JWTSecret:       testSecret,
		Issuer:          testIssuer,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
}

func testUser(id string, role models.Role) models.User {
	return models.User{
		ID:      id,
		IsAdmin: role == models.RoleAdmin,
		Role:    role,
	}
}

func parseClaims(t *testing.T, svc *TokenService, tokenString string) *Claims {
	t.Helper()

	claims := new(Claims)
	token, err := gojwt.ParseWithClaims(tokenString, claims, func(token *gojwt.Token) (any, error) {
		return svc.secret, nil
	})
	if err != nil {
		t.Fatalf("parsing token claims: %v", err)
	}
	if !token.Valid {
		t.Fatal("expected token to be valid")
	}
	return claims
}

func TestNewTokenService(t *testing.T) {
	svc := mustService(t)

	if string(svc.secret) != testSecret {
		t.Fatalf("expected configured secret to be stored")
	}
	if svc.issuer != testIssuer {
		t.Fatalf("expected issuer %q, got %q", testIssuer, svc.issuer)
	}
	if svc.accessTokenTTL != 15*time.Minute {
		t.Fatalf("expected access TTL 15m, got %s", svc.accessTokenTTL)
	}
	if svc.refreshTokenTTL != 30*24*time.Hour {
		t.Fatalf("expected refresh TTL 720h, got %s", svc.refreshTokenTTL)
	}
}

func TestIssuePairAndParseAccessToken(t *testing.T) {
	svc := mustService(t)
	now := time.Now().UTC()

	pair, err := svc.IssuePair(testUser("user-123", models.RoleAdmin), now)
	if err != nil {
		t.Fatalf("IssuePair returned error: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty token pair")
	}
	if pair.AccessTokenExpiresAt.Before(now) || pair.AccessTokenExpiresAt.After(now.Add(svc.accessTokenTTL).Add(time.Second)) {
		t.Fatalf("access token expiry not based on configured TTL: %s", pair.AccessTokenExpiresAt)
	}
	if pair.RefreshTokenExpiresAt.Before(now) || pair.RefreshTokenExpiresAt.After(now.Add(svc.refreshTokenTTL).Add(time.Second)) {
		t.Fatalf("refresh token expiry not based on configured TTL: %s", pair.RefreshTokenExpiresAt)
	}
	if !bytes.Equal(HashRefreshToken(pair.RefreshToken), pair.RefreshTokenHash) {
		t.Fatal("refresh token hash does not match refresh token")
	}

	principal, err := svc.ParseAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccessToken returned error: %v", err)
	}
	if principal.ID != "user-123" {
		t.Errorf("expected principal ID user-123, got %q", principal.ID)
	}
	if principal.Role != models.RoleAdmin {
		t.Errorf("expected role admin, got %q", principal.Role)
	}

	claims := parseClaims(t, svc, pair.AccessToken)
	if claims.Subject != "user-123" {
		t.Errorf("expected subject user-123, got %q", claims.Subject)
	}
	if !claims.IsAdmin {
		t.Error("expected is_admin claim to remain true")
	}
	if claims.Role != string(models.RoleAdmin) {
		t.Errorf("expected role claim admin, got %q", claims.Role)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("expected issuer %q, got %q", testIssuer, claims.Issuer)
	}
}

func TestTokensAreUnique(t *testing.T) {
	svc := mustService(t)
	user := testUser("user-123", models.RoleUser)
	now := time.Now().UTC()

	pair1, err := svc.IssuePair(user, now)
	if err != nil {
		t.Fatalf("IssuePair returned error: %v", err)
	}
	pair2, err := svc.IssuePair(user, now)
	if err != nil {
		t.Fatalf("IssuePair returned error: %v", err)
	}

	if pair1.AccessToken == pair2.AccessToken {
		t.Error("two access tokens issued back-to-back are identical; jti missing?")
	}
	if pair1.RefreshToken == pair2.RefreshToken {
		t.Error("two refresh tokens issued back-to-back are identical")
	}
}

func TestRoleFallsBackToIsAdmin(t *testing.T) {
	svc := mustService(t)
	user := models.User{ID: "user-123", IsAdmin: true}

	token, _, err := svc.IssueAccessToken(user, time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	principal, err := svc.ParseAccessToken(token)
	if err != nil {
		t.Fatalf("ParseAccessToken returned error: %v", err)
	}
	if principal.Role != models.RoleAdmin {
		t.Fatalf("expected role admin fallback, got %q", principal.Role)
	}
}

func TestParseExpiredToken(t *testing.T) {
	svc := mustService(t)
	svc.accessTokenTTL = -time.Minute

	token, _, err := svc.IssueAccessToken(testUser("user-123", models.RoleUser), time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if _, err := svc.ParseAccessToken(token); err == nil {
		t.Fatal("expected error parsing expired token, got nil")
	}
}

func TestWrongSignatureRejected(t *testing.T) {
	svc := mustService(t)

	other := *svc
	other.secret = []byte("a-completely-different-secret-key-value")

	token, _, err := other.IssueAccessToken(testUser("user-123", models.RoleUser), time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if _, err := svc.ParseAccessToken(token); err == nil {
		t.Fatal("expected error for wrong signature, got nil")
	}
}

func TestAlgNoneRejected(t *testing.T) {
	svc := mustService(t)

	claims := Claims{
		Role:      string(models.RoleUser),
		TokenType: accessTokenType,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    testIssuer,
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned := gojwt.NewWithClaims(gojwt.SigningMethodNone, claims)
	token, err := unsigned.SignedString(gojwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing alg=none token: %v", err)
	}

	if _, err := svc.ParseAccessToken(token); err == nil {
		t.Fatal("alg=none token was accepted; expected rejection")
	}
}

func TestIssuerMismatchRejected(t *testing.T) {
	svc := mustService(t)

	other := *svc
	other.issuer = "some-other-service"

	token, _, err := other.IssueAccessToken(testUser("user-123", models.RoleUser), time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if _, err := svc.ParseAccessToken(token); err == nil {
		t.Fatal("token with wrong issuer was accepted; expected rejection")
	}
}

func TestParseInvalidInput(t *testing.T) {
	svc := mustService(t)

	if _, err := svc.ParseAccessToken(""); err == nil {
		t.Error("expected error for empty token, got nil")
	}
	if _, err := svc.ParseAccessToken("not-a-jwt"); err == nil {
		t.Error("expected error for malformed token, got nil")
	}
}
