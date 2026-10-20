// Package sqldb provides database operations for the IAM service.
package sqldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // Register the pgx database/sql driver.

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

// PostgreSQL SQLSTATE integrity-constraint violation codes.
const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"
)

var (
	// ErrNotFound reports that a requested database row does not exist.
	ErrNotFound = sql.ErrNoRows
	// ErrDuplicate reports a uniqueness-constraint violation.
	ErrDuplicate = errors.New("duplicate entry")
	// ErrForeignKeyViolation reports a foreign-key constraint violation.
	ErrForeignKeyViolation = errors.New("foreign key violation")
)

// Store persists IAM users, tokens, and transactional outbox records.
// Callers should define the smallest interface they need rather than depending
// on Store's complete method set.
type Store struct {
	db       *sql.DB
	database string
}

// New opens and verifies a PostgreSQL-backed Store.
func New(ctx context.Context, cfg config.DB) (*Store, error) {
	connectionURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.Username, cfg.Password),
		Host:   net.JoinHostPort(cfg.Host, cfg.Port),
		Path:   cfg.Database,
	}
	query := connectionURL.Query()
	query.Set("sslmode", cfg.SSLMode)
	query.Set("search_path", cfg.Schema)
	connectionURL.RawQuery = query.Encode()

	db, err := sql.Open("pgx", connectionURL.String())
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Bound the pool so a traffic spike queues here instead of exhausting
	// Postgres connections.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Fail fast on bad credentials or an unreachable host rather than
	// surfacing the problem on the first query.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging database %q at %s: %w", cfg.Database, connectionURL.Host, err)
	}

	return &Store{
		db:       db,
		database: cfg.Database,
	}, nil
}

// Ping verifies that the database is reachable using ctx.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// Stats returns the current database connection-pool statistics.
func (s *Store) Stats() sql.DBStats {
	return s.db.Stats()
}

// Close closes the database connection pool.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing database %q: %w", s.database, err)
	}
	return nil
}

// ---------------------------------------------
// SQL Commands
// ---------------------------------------------

// GetUserByID retrieves a user by their ID.
func (s *Store) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	const query = `
		SELECT
			id::text,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			avatar_photo_id,
			is_admin,
			role,
			created_at,
			updated_at
		FROM auth.users
		WHERE id = $1
	`

	user, err := scanUser(s.db.QueryRowContext(ctx, query, userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrNotFound
		}
		return models.User{}, fmt.Errorf("selecting user: %w", err)
	}

	return user, nil
}

// GetUserByEmail retrieves a user by their email address.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	const query = `
		SELECT
			id::text,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			avatar_photo_id,
			is_admin,
			role,
			created_at,
			updated_at
		FROM auth.users
		WHERE email = $1
	`

	user, err := scanUser(s.db.QueryRowContext(ctx, query, email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrNotFound
		}
		return models.User{}, fmt.Errorf("selecting user by email: %w", err)
	}

	return user, nil
}

// GetUserByAccount retrieves a user by their account name.
func (s *Store) GetUserByAccount(ctx context.Context, account string) (models.User, error) {
	const query = `
		SELECT
			id::text,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			avatar_photo_id,
			is_admin,
			role,
			created_at,
			updated_at
		FROM auth.users
		WHERE account = $1
	`

	user, err := scanUser(s.db.QueryRowContext(ctx, query, account))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrNotFound
		}
		return models.User{}, fmt.Errorf("selecting user by account: %w", err)
	}

	return user, nil
}

// CreateUser inserts a new user into the database.
func (s *Store) CreateUser(ctx context.Context, newUser models.NewUser, eventFn OutboxEventFunc) (models.User, error) {
	return s.mutateWithOutbox(ctx, eventFn, func(q querier) (models.User, error) {
		const query = `
			INSERT INTO auth.users (name, account, email, password, is_admin)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id::text, name, account, email, password, bio, dob, city, phone, avatar_photo_id, is_admin, role, created_at, updated_at
		`

		user, err := scanUser(q.QueryRowContext(ctx, query,
			newUser.Name,
			newUser.Account,
			newUser.Email,
			newUser.Password,
			false, // is_admin defaults to false
		))
		if err != nil {
			if isPgError(err, uniqueViolation) {
				return models.User{}, ErrDuplicate
			}
			return models.User{}, fmt.Errorf("creating user: %w", err)
		}

		return user, nil
	})
}

// ListUsers retrieves all users from the database.
func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	const query = `
		SELECT
			id::text,
			name,
			account,
			email,
			bio,
			dob,
			city,
			phone,
			avatar_photo_id,
			is_admin,
			role,
			created_at,
			updated_at
		FROM auth.users
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	users := make([]models.User, 0)
	for rows.Next() {
		user, err := scanUserWithoutPassword(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating users: %w", err)
	}

	return users, nil
}

// UpdateUser updates a user's profile fields.
func (s *Store) UpdateUser(ctx context.Context, userID string, update models.UpdateUser, eventFn OutboxEventFunc) (models.User, error) {
	return s.mutateWithOutbox(ctx, eventFn, func(q querier) (models.User, error) {
		const query = `
			UPDATE auth.users
			SET name    = $1,
			    account = $2,
			    bio     = $3,
			    dob     = $4,
			    city    = $5,
			    phone   = $6,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = $7
			RETURNING id::text, name, account, email, password, bio, dob, city, phone, avatar_photo_id, is_admin, role, created_at, updated_at
		`

		user, err := scanUser(q.QueryRowContext(ctx, query,
			update.Name,
			update.Account,
			update.Bio,
			update.DOB,
			update.City,
			update.Phone,
			userID,
		))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return models.User{}, ErrNotFound
			}
			if isPgError(err, uniqueViolation) {
				return models.User{}, ErrDuplicate
			}
			return models.User{}, fmt.Errorf("updating user: %w", err)
		}

		return user, nil
	})
}

// PromoteUserToAdmin sets the is_admin flag to true for a specific user.
func (s *Store) PromoteUserToAdmin(ctx context.Context, userID string, eventFn OutboxEventFunc) (models.User, error) {
	return s.setAdminFlag(ctx, userID, true, eventFn)
}

// DemoteUserFromAdmin sets the is_admin flag to false for a specific user.
func (s *Store) DemoteUserFromAdmin(ctx context.Context, userID string, eventFn OutboxEventFunc) (models.User, error) {
	return s.setAdminFlag(ctx, userID, false, eventFn)
}

func (s *Store) setAdminFlag(ctx context.Context, userID string, isAdmin bool, eventFn OutboxEventFunc) (models.User, error) {
	return s.mutateWithOutbox(ctx, eventFn, func(q querier) (models.User, error) {
		const query = `
			UPDATE auth.users
			SET is_admin = $1,
			    role = $2,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = $3
			RETURNING id::text, name, account, email, password, bio, dob, city, phone, avatar_photo_id, is_admin, role, created_at, updated_at
		`

		user, err := scanUser(q.QueryRowContext(ctx, query, isAdmin, roleFromAdmin(isAdmin), userID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return models.User{}, ErrNotFound
			}
			return models.User{}, fmt.Errorf("setting admin flag: %w", err)
		}

		return user, nil
	})
}

// ---------------------------------------------
// Refresh Token Operations
// ---------------------------------------------

// CreateRefreshToken inserts a new refresh token into the database.
func (s *Store) CreateRefreshToken(ctx context.Context, newRefreshToken models.NewRefreshToken) (models.RefreshToken, error) {
	const query = `
		INSERT INTO auth.refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id::text, user_id::text, token, expires_at, revoked_at, created_at, updated_at
	`

	// Store only the hash of the bearer token. The plaintext is returned to the
	// client once at issuance and never persisted, so a DB compromise alone
	// cannot be used to authenticate as a user.
	refreshToken, err := scanRefreshToken(s.db.QueryRowContext(ctx, query,
		newRefreshToken.UserID,
		hashTokenBytes(newRefreshToken.Token),
		newRefreshToken.ExpiresAt,
	))

	if err != nil {
		if isPgError(err, foreignKeyViolation) {
			return models.RefreshToken{}, ErrForeignKeyViolation
		}
		if isPgError(err, uniqueViolation) {
			return models.RefreshToken{}, ErrDuplicate
		}
		return models.RefreshToken{}, fmt.Errorf("creating refresh token: %w", err)
	}

	return refreshToken, nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token value.
func (s *Store) GetRefreshTokenByToken(ctx context.Context, token []byte) (models.RefreshToken, error) {
	const query = `
		SELECT
			id::text,
			user_id::text,
			token,
			expires_at,
			revoked_at,
			created_at,
			updated_at
		FROM auth.refresh_tokens
		WHERE token = $1
	`

	// Callers pass the plaintext bearer token; we look up by its SHA-256 hash
	// because that's what's stored.
	refreshToken, err := scanRefreshToken(s.db.QueryRowContext(ctx, query, hashTokenBytes(token)))

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.RefreshToken{}, ErrNotFound
		}
		return models.RefreshToken{}, fmt.Errorf("getting refresh token: %w", err)
	}

	return refreshToken, nil
}

// RotateRefreshToken atomically revokes currentTokenID and inserts its
// replacement. The conditional UPDATE ensures concurrent uses of the same
// token cannot both mint a new session.
func (s *Store) RotateRefreshToken(ctx context.Context, currentTokenID string, newToken models.NewRefreshToken) (models.RefreshToken, error) {
	const query = `
		WITH revoked AS (
			UPDATE auth.refresh_tokens
			SET revoked_at = CURRENT_TIMESTAMP,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
			AND user_id = $2
			AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP
			RETURNING user_id
		)
		INSERT INTO auth.refresh_tokens (user_id, token, expires_at)
		SELECT user_id, $3, $4 FROM revoked
		RETURNING id::text, user_id::text, token, expires_at, revoked_at, created_at, updated_at
	`

	rotated, err := scanRefreshToken(s.db.QueryRowContext(
		ctx,
		query,
		currentTokenID,
		newToken.UserID,
		hashTokenBytes(newToken.Token),
		newToken.ExpiresAt,
	))
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return models.RefreshToken{}, ErrNotFound
		case isPgError(err, uniqueViolation):
			return models.RefreshToken{}, ErrDuplicate
		default:
			return models.RefreshToken{}, fmt.Errorf("rotating refresh token: %w", err)
		}
	}

	return rotated, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	const query = `
		UPDATE auth.refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteExpiredRefreshTokens removes all expired refresh tokens from the database.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) error {
	const query = `
		DELETE FROM auth.refresh_tokens
		WHERE expires_at < CURRENT_TIMESTAMP
	`

	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("deleting expired refresh tokens: %w", err)
	}

	return nil
}

// DeleteRefreshTokensByUserID removes all refresh tokens for a specific user.
func (s *Store) DeleteRefreshTokensByUserID(ctx context.Context, userID string) error {
	return deleteRefreshTokensByUserID(ctx, s.db, userID)
}

func deleteRefreshTokensByUserID(ctx context.Context, q querier, userID string) error {
	const query = `
		DELETE FROM auth.refresh_tokens
		WHERE user_id = $1
	`

	_, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("deleting refresh tokens for user: %w", err)
	}

	return nil
}

// ---------------------------------------------
// Password Reset Token Operations
// ---------------------------------------------

// CreatePasswordResetToken inserts a new password reset token into the database.
func (s *Store) CreatePasswordResetToken(ctx context.Context, newToken models.NewPasswordResetToken) (models.PasswordResetToken, error) {
	const query = `
		INSERT INTO auth.password_reset_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id::text, user_id::text, token, expires_at, used_at, created_at
	`

	var token models.PasswordResetToken
	// Only the hash is persisted; the plaintext is emailed to the user and
	// then thrown away. See refresh-token rationale above.
	err := s.db.QueryRowContext(ctx, query,
		newToken.UserID,
		hashTokenString(newToken.Token),
		newToken.ExpiresAt,
	).Scan(
		&token.ID,
		&token.UserID,
		&token.Token,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		if isPgError(err, foreignKeyViolation) {
			return models.PasswordResetToken{}, ErrForeignKeyViolation
		}
		return models.PasswordResetToken{}, fmt.Errorf("creating password reset token: %w", err)
	}

	return token, nil
}

// ConsumePasswordResetToken atomically redeems an unused, unexpired reset
// token by stamping used_at in the same statement that looks it up. Two
// concurrent requests presenting the same token can't both succeed: the
// second UPDATE matches zero rows and gets ErrNotFound.
func (s *Store) ConsumePasswordResetToken(ctx context.Context, token string) (models.PasswordResetToken, error) {
	return consumePasswordResetToken(ctx, s.db, token)
}

func consumePasswordResetToken(ctx context.Context, q querier, token string) (models.PasswordResetToken, error) {
	const query = `
		UPDATE auth.password_reset_tokens
		SET used_at = CURRENT_TIMESTAMP
		WHERE token = $1
		AND used_at IS NULL
		AND expires_at > CURRENT_TIMESTAMP
		RETURNING id::text, user_id::text, token, expires_at, used_at, created_at
	`

	var resetToken models.PasswordResetToken
	err := q.QueryRowContext(ctx, query, hashTokenString(token)).Scan(
		&resetToken.ID,
		&resetToken.UserID,
		&resetToken.Token,
		&resetToken.ExpiresAt,
		&resetToken.UsedAt,
		&resetToken.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.PasswordResetToken{}, ErrNotFound
		}
		return models.PasswordResetToken{}, fmt.Errorf("consuming password reset token: %w", err)
	}

	return resetToken, nil
}

// ResetPassword atomically consumes a reset token, changes the password, and
// revokes every existing refresh token. Any failure rolls the whole operation
// back, so a transient database error cannot burn the one-time token.
func (s *Store) ResetPassword(ctx context.Context, token string, newPassword []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning password reset transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	resetToken, err := consumePasswordResetToken(ctx, tx, token)
	if err != nil {
		return err
	}
	if err := updateUserPassword(ctx, tx, resetToken.UserID, newPassword); err != nil {
		return err
	}
	if err := deleteRefreshTokensByUserID(ctx, tx, resetToken.UserID); err != nil {
		return err
	}
	if err := deletePasswordResetTokensByUserID(ctx, tx, resetToken.UserID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing password reset transaction: %w", err)
	}
	return nil
}

func deletePasswordResetTokensByUserID(ctx context.Context, q querier, userID string) error {
	const query = `
		DELETE FROM auth.password_reset_tokens
		WHERE user_id = $1
	`

	if _, err := q.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("deleting password reset tokens for user: %w", err)
	}
	return nil
}

// DeleteExpiredPasswordResetTokens removes all expired or used password reset tokens.
func (s *Store) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	const query = `
		DELETE FROM auth.password_reset_tokens
		WHERE expires_at < CURRENT_TIMESTAMP OR used_at IS NOT NULL
	`

	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("deleting expired password reset tokens: %w", err)
	}

	return nil
}

// ---------------------------------------------
// Password Operations
// ---------------------------------------------

// UpdateUserPassword updates a user's password.
func (s *Store) UpdateUserPassword(ctx context.Context, userID string, newPassword []byte) error {
	return updateUserPassword(ctx, s.db, userID, newPassword)
}

func updateUserPassword(ctx context.Context, q querier, userID string, newPassword []byte) error {
	const query = `
		UPDATE auth.users
		SET password = $1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	result, err := q.ExecContext(ctx, query, newPassword, userID)
	if err != nil {
		return fmt.Errorf("updating user password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateUserPasswordAndRevokeTokens changes a password and invalidates all
// refresh sessions in one transaction.
func (s *Store) UpdateUserPasswordAndRevokeTokens(ctx context.Context, userID string, newPassword []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning password change transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	if err := updateUserPassword(ctx, tx, userID, newPassword); err != nil {
		return err
	}
	if err := deleteRefreshTokensByUserID(ctx, tx, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing password change transaction: %w", err)
	}
	return nil
}

// ---------------------------------------------
// Helpers
// ---------------------------------------------

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner rowScanner) (models.User, error) {
	var user models.User
	var bio, dob, city, phone sql.NullString
	var avatarPhotoID sql.NullInt32
	if err := scanner.Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&user.Password,
		&bio,
		&dob,
		&city,
		&phone,
		&avatarPhotoID,
		&user.IsAdmin,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return models.User{}, err
	}

	user.Bio = stringPtr(bio)
	user.DOB = stringPtr(dob)
	user.City = stringPtr(city)
	user.Phone = stringPtr(phone)
	user.AvatarPhotoID = int32Ptr(avatarPhotoID)

	return user, nil
}

func scanUserWithoutPassword(scanner rowScanner) (models.User, error) {
	var user models.User
	var bio, dob, city, phone sql.NullString
	var avatarPhotoID sql.NullInt32
	if err := scanner.Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&bio,
		&dob,
		&city,
		&phone,
		&avatarPhotoID,
		&user.IsAdmin,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return models.User{}, err
	}

	user.Bio = stringPtr(bio)
	user.DOB = stringPtr(dob)
	user.City = stringPtr(city)
	user.Phone = stringPtr(phone)
	user.AvatarPhotoID = int32Ptr(avatarPhotoID)

	return user, nil
}

func roleFromAdmin(isAdmin bool) models.Role {
	if isAdmin {
		return models.RoleAdmin
	}
	return models.RoleUser
}

func scanRefreshToken(scanner rowScanner) (models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	if err := scanner.Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.ExpiresAt,
		&refreshToken.RevokedAt,
		&refreshToken.CreatedAt,
		&refreshToken.UpdatedAt,
	); err != nil {
		return models.RefreshToken{}, err
	}

	return refreshToken, nil
}

// isPgError checks if the error is a PostgreSQL error with the given code.
func isPgError(err error, code string) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == code
	}
	return false
}

func stringPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func int32Ptr(ni sql.NullInt32) *int {
	if !ni.Valid {
		return nil
	}
	intVal := int(ni.Int32)
	return &intVal
}
