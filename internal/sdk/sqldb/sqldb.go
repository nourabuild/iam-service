// Package sqldb provides database operations for the IAM service.
package sqldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

// lib/pq errorCodeNames
// https://github.com/lib/pq/blob/master/error.go#L178
const (
	uniqueViolation     = "23505"
	undefinedTable      = "42P01"
	foreignKeyViolation = "23503"
	checkViolation      = "23514"
	notNullViolation    = "23502"
)

var (
	ErrDBNotFound          = sql.ErrNoRows
	ErrDBDuplicatedEntry   = errors.New("duplicated entry")
	ErrUndefinedTable      = errors.New("undefined table")
	ErrForeignKeyViolation = errors.New("foreign key violation")
	ErrCheckViolation      = errors.New("check constraint violation")
	ErrNotNullViolation    = errors.New("not null violation")
	ErrTransactionFailed   = errors.New("transaction failed")
)

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	// The keys and values in the map are service-specific.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error

	// User operations
	GetUserByID(ctx context.Context, userID string) (models.User, error)
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	GetUserByAccount(ctx context.Context, account string) (models.User, error)
	CreateUser(ctx context.Context, user models.NewUser) (models.User, error)
	ListUsers(ctx context.Context) ([]models.User, error)

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, token models.NewRefreshToken) (models.RefreshToken, error)
	GetRefreshTokenByToken(ctx context.Context, token []byte) (models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	DeleteExpiredRefreshTokens(ctx context.Context) error
	DeleteRefreshTokensByUserID(ctx context.Context, userID string) error
}

type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("BLUEPRINT_DB_DATABASE")
	password   = os.Getenv("BLUEPRINT_DB_PASSWORD")
	username   = os.Getenv("BLUEPRINT_DB_USERNAME")
	port       = os.Getenv("BLUEPRINT_DB_PORT")
	host       = os.Getenv("BLUEPRINT_DB_HOST")
	schema     = os.Getenv("BLUEPRINT_DB_SCHEMA")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}
	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf("db down: %v", err) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}

// ---------------------------------------------
// SQL Commands
// ---------------------------------------------

// SelectMe retrieves a user by their ID
func (s *service) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	const query = `
		SELECT
			id,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			is_admin,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`

	var user models.User
	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&user.Password,
		&user.Bio,
		&user.DOB,
		&user.City,
		&user.Phone,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrDBNotFound
		}
		return models.User{}, fmt.Errorf("selecting user: %w", err)
	}

	return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (s *service) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	const query = `
		SELECT
			id,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			is_admin,
			created_at,
			updated_at
		FROM users
		WHERE email = $1
	`

	var user models.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&user.Password,
		&user.Bio,
		&user.DOB,
		&user.City,
		&user.Phone,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrDBNotFound
		}
		return models.User{}, fmt.Errorf("selecting user by email: %w", err)
	}

	return user, nil
}

// GetUserByAccount retrieves a user by their account name
func (s *service) GetUserByAccount(ctx context.Context, account string) (models.User, error) {
	const query = `
		SELECT
			id,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			is_admin,
			created_at,
			updated_at
		FROM users
		WHERE account = $1
	`

	var user models.User
	err := s.db.QueryRowContext(ctx, query, account).Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&user.Password,
		&user.Bio,
		&user.DOB,
		&user.City,
		&user.Phone,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, ErrDBNotFound
		}
		return models.User{}, fmt.Errorf("selecting user by account: %w", err)
	}

	return user, nil
}

// CreateUser inserts a new user into the database
func (s *service) CreateUser(ctx context.Context, nu models.NewUser) (models.User, error) {
	const query = `
		INSERT INTO users (name, account, email, password, is_admin)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, account, email, password, bio, dob, city, phone, is_admin, created_at, updated_at
	`

	var user models.User

	err := s.db.QueryRowContext(ctx, query,
		nu.Name,
		nu.Account,
		nu.Email,
		nu.Password,
		false, // is_admin defaults to false
	).Scan(
		&user.ID,
		&user.Name,
		&user.Account,
		&user.Email,
		&user.Password,
		&user.Bio,
		&user.DOB,
		&user.City,
		&user.Phone,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if isPgError(err, uniqueViolation) {
			return models.User{}, ErrDBDuplicatedEntry
		}
		return models.User{}, fmt.Errorf("creating user: %w", err)
	}

	return user, nil
}

// ListUsers retrieves all users from the database
func (s *service) ListUsers(ctx context.Context) ([]models.User, error) {
	const query = `
		SELECT
			id,
			name,
			account,
			email,
			password,
			bio,
			dob,
			city,
			phone,
			is_admin,
			created_at,
			updated_at
		FROM users
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Account,
			&user.Email,
			&user.Password,
			&user.Bio,
			&user.DOB,
			&user.City,
			&user.Phone,
			&user.IsAdmin,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
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

// ---------------------------------------------
// Refresh Token Operations
// ---------------------------------------------

// CreateRefreshToken inserts a new refresh token into the database
func (s *service) CreateRefreshToken(ctx context.Context, nrt models.NewRefreshToken) (models.RefreshToken, error) {
	const query = `
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, token, expires_at, revoked_at, created_at, updated_at
	`

	var rt models.RefreshToken
	err := s.db.QueryRowContext(ctx, query,
		nrt.UserID,
		nrt.Token,
		nrt.ExpiresAt,
	).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
		&rt.RevokedAt,
		&rt.CreatedAt,
		&rt.UpdatedAt,
	)

	if err != nil {
		if isPgError(err, foreignKeyViolation) {
			return models.RefreshToken{}, ErrForeignKeyViolation
		}
		return models.RefreshToken{}, fmt.Errorf("creating refresh token: %w", err)
	}

	return rt, nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token value
func (s *service) GetRefreshTokenByToken(ctx context.Context, token []byte) (models.RefreshToken, error) {
	const query = `
		SELECT
			id,
			user_id,
			token,
			expires_at,
			revoked_at,
			created_at,
			updated_at
		FROM refresh_tokens
		WHERE token = $1
	`

	var rt models.RefreshToken
	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
		&rt.RevokedAt,
		&rt.CreatedAt,
		&rt.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.RefreshToken{}, ErrDBNotFound
		}
		return models.RefreshToken{}, fmt.Errorf("getting refresh token: %w", err)
	}

	return rt, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func (s *service) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	const query = `
		UPDATE refresh_tokens
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
		return ErrDBNotFound
	}

	return nil
}

// DeleteExpiredRefreshTokens removes all expired refresh tokens from the database
func (s *service) DeleteExpiredRefreshTokens(ctx context.Context) error {
	const query = `
		DELETE FROM refresh_tokens
		WHERE expires_at < CURRENT_TIMESTAMP
	`

	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("deleting expired refresh tokens: %w", err)
	}

	return nil
}

// DeleteRefreshTokensByUserID removes all refresh tokens for a specific user
func (s *service) DeleteRefreshTokensByUserID(ctx context.Context, userID string) error {
	const query = `
		DELETE FROM refresh_tokens
		WHERE user_id = $1
	`

	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("deleting refresh tokens for user: %w", err)
	}

	return nil
}

// ---------------------------------------------
// Helpers
// ---------------------------------------------

// isPgError checks if the error is a PostgreSQL error with the given code
func isPgError(err error, code string) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == code
	}
	return false
}

// NullString creates a sql.NullString from a string pointer.
func NullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// NullInt64 creates a sql.NullInt64 from an int64 pointer.
func NullInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

// NullFloat64 creates a sql.NullFloat64 from a float64 pointer.
func NullFloat64(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}

// NullBool creates a sql.NullBool from a bool pointer.
func NullBool(b *bool) sql.NullBool {
	if b == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *b, Valid: true}
}

// NullTime creates a sql.NullTime from a time.Time pointer.
func NullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// StringPtr returns a pointer to a string from sql.NullString.
func StringPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// Int64Ptr returns a pointer to an int64 from sql.NullInt64.
func Int64Ptr(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int64
}

// Float64Ptr returns a pointer to a float64 from sql.NullFloat64.
func Float64Ptr(nf sql.NullFloat64) *float64 {
	if !nf.Valid {
		return nil
	}
	return &nf.Float64
}

// BoolPtr returns a pointer to a bool from sql.NullBool.
func BoolPtr(nb sql.NullBool) *bool {
	if !nb.Valid {
		return nil
	}
	return &nb.Bool
}

// TimePtr returns a pointer to a time.Time from sql.NullTime.
func TimePtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

// IsNotFound checks if the error is a not found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrDBNotFound)
}

// IsDuplicateEntry checks if the error is a duplicate entry error.
func IsDuplicateEntry(err error) bool {
	return isPgError(err, uniqueViolation)
}

// IsForeignKeyViolation checks if the error is a foreign key violation error.
func IsForeignKeyViolation(err error) bool {
	return isPgError(err, foreignKeyViolation)
}

// IsUndefinedTable checks if the error is an undefined table error.
func IsUndefinedTable(err error) bool {
	return isPgError(err, undefinedTable)
}

// IsCheckViolation checks if the error is a check constraint violation error.
func IsCheckViolation(err error) bool {
	return isPgError(err, checkViolation)
}

// IsNotNullViolation checks if the error is a not null violation error.
func IsNotNullViolation(err error) bool {
	return isPgError(err, notNullViolation)
}
