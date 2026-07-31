package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

type refreshHandlerDBStub struct {
	sqldb.Service
	getRefreshTokenByTokenFn    func(context.Context, []byte) (models.RefreshToken, error)
	deleteRefreshTokensByUserID func(context.Context, string) error
	getUserByIDFn               func(context.Context, string) (models.User, error)
	rotateRefreshTokenFn        func(context.Context, string, models.NewRefreshToken) (models.RefreshToken, error)
}

func (s *refreshHandlerDBStub) GetRefreshTokenByToken(
	ctx context.Context,
	token []byte,
) (models.RefreshToken, error) {
	return s.getRefreshTokenByTokenFn(ctx, token)
}

func (s *refreshHandlerDBStub) DeleteRefreshTokensByUserID(ctx context.Context, userID string) error {
	return s.deleteRefreshTokensByUserID(ctx, userID)
}

func (s *refreshHandlerDBStub) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	return s.getUserByIDFn(ctx, userID)
}

func (s *refreshHandlerDBStub) RotateRefreshToken(
	ctx context.Context,
	currentTokenID string,
	token models.NewRefreshToken,
) (models.RefreshToken, error) {
	return s.rotateRefreshTokenFn(ctx, currentTokenID, token)
}

type refreshIssuerStub struct {
	jwt.TokenRepository
	issuePairFn func(models.User, time.Time) (jwt.TokenPair, error)
}

func (s *refreshIssuerStub) IssuePair(user models.User, now time.Time) (jwt.TokenPair, error) {
	return s.issuePairFn(user, now)
}

func refreshHandlerRouter(a *App) *gin.Engine {
	router := gin.New()
	router.POST("/refresh", a.HandleRefresh)
	return router
}

func TestHandleRefreshFailureBranches(t *testing.T) {
	errDelete := errors.New("delete refresh sessions")
	errRotate := errors.New("rotate refresh token")

	tests := []struct {
		name          string
		revoked       bool
		deleteErr     error
		getUserErr    error
		rotateErr     error
		wantStatus    int
		wantError     string
		wantDeletes   int
		wantUserReads int
		wantIssues    int
		wantRotations int
	}{
		{
			name:        "revoked token still rejects replay when session deletion fails",
			revoked:     true,
			deleteErr:   errDelete,
			wantStatus:  http.StatusUnauthorized,
			wantError:   "invalid_token",
			wantDeletes: 1,
		},
		{
			name:          "refresh token references missing user",
			getUserErr:    sqldb.ErrDBNotFound,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantUserReads: 1,
		},
		{
			name:          "concurrent rotation consumed token first",
			rotateErr:     sqldb.ErrDBNotFound,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantUserReads: 1,
			wantIssues:    1,
			wantRotations: 1,
		},
		{
			name:          "rotation database failure",
			rotateErr:     errRotate,
			wantStatus:    http.StatusInternalServerError,
			wantError:     "internal_generate_tokens_error",
			wantUserReads: 1,
			wantIssues:    1,
			wantRotations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				presentedToken = "presented-refresh-token"
				storedTokenID  = "stored-token-id"
				userID         = "user-id"
				newToken       = "new-refresh-token"
			)

			now := time.Now().UTC()
			storedToken := models.RefreshToken{
				ID:        storedTokenID,
				UserID:    userID,
				Token:     []byte(presentedToken),
				ExpiresAt: now.Add(time.Hour),
			}
			if tt.revoked {
				revokedAt := now.Add(-time.Minute)
				storedToken.RevokedAt = &revokedAt
			}
			pair := jwt.TokenPair{
				AccessToken:           "new-access-token",
				RefreshToken:          newToken,
				RefreshTokenExpiresAt: now.Add(24 * time.Hour),
			}

			tokenReads := 0
			deletes := 0
			userReads := 0
			issues := 0
			rotations := 0
			var rotatedTokenID string
			var rotatedToken models.NewRefreshToken

			db := &refreshHandlerDBStub{
				getRefreshTokenByTokenFn: func(_ context.Context, token []byte) (models.RefreshToken, error) {
					tokenReads++
					if !bytes.Equal(token, []byte(presentedToken)) {
						t.Fatalf("looked up token = %q, want %q", token, presentedToken)
					}
					return storedToken, nil
				},
				deleteRefreshTokensByUserID: func(_ context.Context, gotUserID string) error {
					deletes++
					if gotUserID != userID {
						t.Fatalf("deleted sessions for user = %q, want %q", gotUserID, userID)
					}
					return tt.deleteErr
				},
				getUserByIDFn: func(_ context.Context, gotUserID string) (models.User, error) {
					userReads++
					if gotUserID != userID {
						t.Fatalf("loaded user = %q, want %q", gotUserID, userID)
					}
					if tt.getUserErr != nil {
						return models.User{}, tt.getUserErr
					}
					return models.User{ID: userID}, nil
				},
				rotateRefreshTokenFn: func(
					_ context.Context,
					currentTokenID string,
					token models.NewRefreshToken,
				) (models.RefreshToken, error) {
					rotations++
					rotatedTokenID = currentTokenID
					rotatedToken = token
					if tt.rotateErr != nil {
						return models.RefreshToken{}, tt.rotateErr
					}
					return models.RefreshToken{ID: "rotated-token-id"}, nil
				},
			}
			issuer := &refreshIssuerStub{
				issuePairFn: func(user models.User, issuedAt time.Time) (jwt.TokenPair, error) {
					issues++
					if user.ID != userID {
						t.Fatalf("issued pair for user = %q, want %q", user.ID, userID)
					}
					if issuedAt.IsZero() {
						t.Fatal("token pair issue time is zero")
					}
					return pair, nil
				},
			}
			a := NewApp(db, issuer, nil, nil)

			request := httptest.NewRequest(
				http.MethodPost,
				"/refresh",
				bytes.NewBufferString(`{"refresh_token":" `+presentedToken+` "}`),
			)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			refreshHandlerRouter(a).ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", response.Code, tt.wantStatus, response.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshaling response: %v", err)
			}
			if body.Error != tt.wantError {
				t.Fatalf("error = %q, want %q", body.Error, tt.wantError)
			}

			if tokenReads != 1 {
				t.Errorf("refresh token reads = %d, want 1", tokenReads)
			}
			if deletes != tt.wantDeletes {
				t.Errorf("session deletions = %d, want %d", deletes, tt.wantDeletes)
			}
			if userReads != tt.wantUserReads {
				t.Errorf("user reads = %d, want %d", userReads, tt.wantUserReads)
			}
			if issues != tt.wantIssues {
				t.Errorf("token pair issues = %d, want %d", issues, tt.wantIssues)
			}
			if rotations != tt.wantRotations {
				t.Errorf("refresh token rotations = %d, want %d", rotations, tt.wantRotations)
			}

			if tt.wantRotations > 0 {
				if rotatedTokenID != storedTokenID {
					t.Errorf("rotated token ID = %q, want %q", rotatedTokenID, storedTokenID)
				}
				if rotatedToken.UserID != userID {
					t.Errorf("new refresh token user = %q, want %q", rotatedToken.UserID, userID)
				}
				if !bytes.Equal(rotatedToken.Token, []byte(newToken)) {
					t.Errorf("new refresh token = %q, want %q", rotatedToken.Token, newToken)
				}
				if !rotatedToken.ExpiresAt.Equal(pair.RefreshTokenExpiresAt) {
					t.Errorf(
						"new refresh expiry = %s, want %s",
						rotatedToken.ExpiresAt,
						pair.RefreshTokenExpiresAt,
					)
				}
			}
		})
	}
}
