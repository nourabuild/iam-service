package sqldb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testDBName = "database"
	testDBPwd  = "password"
	testDBUser = "user"
)

func mustStartPostgresContainer() (func(context.Context) error, error) {
	dbContainer, err := postgres.Run(
		context.Background(),
		"postgres:17.2",
		postgres.WithDatabase(testDBName),
		postgres.WithUsername(testDBUser),
		postgres.WithPassword(testDBPwd),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		return nil, err
	}

	terminate := func(ctx context.Context) error {
		return dbContainer.Terminate(ctx)
	}

	dbHost, err := dbContainer.Host(context.Background())
	if err != nil {
		return terminate, err
	}

	dbPort, err := dbContainer.MappedPort(context.Background(), "5432/tcp")
	if err != nil {
		return terminate, err
	}

	// New() reads connection settings from the environment at call time.
	os.Setenv("BLUEPRINT_DB_DATABASE", testDBName)
	os.Setenv("BLUEPRINT_DB_PASSWORD", testDBPwd)
	os.Setenv("BLUEPRINT_DB_USERNAME", testDBUser)
	os.Setenv("BLUEPRINT_DB_HOST", dbHost)
	os.Setenv("BLUEPRINT_DB_PORT", dbPort.Port())
	os.Setenv("BLUEPRINT_DB_SCHEMA", "public")
	os.Setenv("BLUEPRINT_DB_SSLMODE", "disable")

	return terminate, nil
}

// runMigrations applies every up-migration in order against the container, so
// the suite tests the schema the service actually runs on — constraint
// regressions fail here.
func runMigrations() error {
	connStr := fmt.Sprintf(
		// simple_protocol lets a single Exec carry the multi-statement
		// migration files.
		"postgres://%s:%s@%s:%s/%s?sslmode=disable&default_query_exec_mode=simple_protocol",
		os.Getenv("BLUEPRINT_DB_USERNAME"),
		os.Getenv("BLUEPRINT_DB_PASSWORD"),
		os.Getenv("BLUEPRINT_DB_HOST"),
		os.Getenv("BLUEPRINT_DB_PORT"),
		os.Getenv("BLUEPRINT_DB_DATABASE"),
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("opening migration connection: %w", err)
	}
	defer db.Close()

	files, err := filepath.Glob("../migrate/sql/*.up.sql")
	if err != nil {
		return fmt.Errorf("globbing migrations: %w", err)
	}
	if len(files) == 0 {
		return errors.New("no migration files found")
	}
	sort.Strings(files)

	for _, file := range files {
		contents, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading %s: %w", file, err)
		}
		if _, err := db.Exec(string(contents)); err != nil {
			return fmt.Errorf("applying %s: %w", file, err)
		}
	}

	return nil
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run()
	cancel()
	if err != nil {
		if os.Getenv("CI") != "" {
			log.Fatalf("Docker is required for sqldb tests in CI: %v", err)
		}
		log.Printf("skipping sqldb integration tests: Docker is unavailable: %v", err)
		return
	}

	teardown, err := mustStartPostgresContainer()
	if err != nil {
		log.Fatalf("could not start postgres container: %v", err)
	}

	if err := runMigrations(); err != nil {
		log.Fatalf("could not run migrations: %v", err)
	}

	code := m.Run()

	if teardown != nil {
		if err := teardown(context.Background()); err != nil {
			log.Printf("could not teardown postgres container: %v", err)
		}
	}

	os.Exit(code)
}

func mustNew(t *testing.T) Service {
	t.Helper()
	srv, err := New(config.LoadDB())
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("closing database: %v", err)
		}
	})
	return srv
}

func createTestUser(t *testing.T, srv Service, account, email string) models.User {
	t.Helper()
	user, err := srv.CreateUser(context.Background(), models.NewUser{
		Name:     "Test User",
		Account:  account,
		Email:    email,
		Password: []byte("not-a-real-hash"),
	}, nil)
	if err != nil {
		t.Fatalf("CreateUser(%s, %s) returned error: %v", account, email, err)
	}
	return user
}

func TestNew(t *testing.T) {
	mustNew(t)
}

func TestHealth(t *testing.T) {
	srv := mustNew(t)

	stats := srv.Health()

	if stats["status"] != "up" {
		t.Fatalf("expected status to be up, got %s", stats["status"])
	}
	if _, ok := stats["error"]; ok {
		t.Fatalf("expected error not to be present")
	}
}

func TestUserLifecycle(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "lifecycle-user", "lifecycle@example.com")
	if user.ID == "" {
		t.Fatal("expected created user to have an ID")
	}
	if user.IsAdmin {
		t.Error("new users must not be admins")
	}

	byEmail, err := srv.GetUserByEmail(ctx, "lifecycle@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail returned error: %v", err)
	}
	if byEmail.ID != user.ID {
		t.Errorf("GetUserByEmail returned wrong user: %s != %s", byEmail.ID, user.ID)
	}

	byID, err := srv.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}
	if byID.Email != "lifecycle@example.com" {
		t.Errorf("GetUserByID returned wrong email: %s", byID.Email)
	}

	if _, err := srv.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("expected ErrDBNotFound for unknown email, got %v", err)
	}

	bio := "hello"
	updated, err := srv.UpdateUser(ctx, user.ID, models.UpdateUser{
		Name:    "Renamed User",
		Account: "lifecycle-user",
		Bio:     &bio,
	}, nil)
	if err != nil {
		t.Fatalf("UpdateUser returned error: %v", err)
	}
	if updated.Name != "Renamed User" || updated.Bio == nil || *updated.Bio != "hello" {
		t.Errorf("UpdateUser did not persist changes: %+v", updated)
	}

	promoted, err := srv.PromoteUserToAdmin(ctx, user.ID, nil)
	if err != nil {
		t.Fatalf("PromoteUserToAdmin returned error: %v", err)
	}
	if !promoted.IsAdmin {
		t.Error("expected promoted user to be admin")
	}

	demoted, err := srv.DemoteUserFromAdmin(ctx, user.ID, nil)
	if err != nil {
		t.Fatalf("DemoteUserFromAdmin returned error: %v", err)
	}
	if demoted.IsAdmin {
		t.Error("expected demoted user to not be admin")
	}
}

// TestEmailUniqueness is the regression test for the original composite
// UNIQUE(email, account) constraint, which allowed two identities to share an
// email as long as the account differed. Migration 000007 must prevent that.
func TestEmailUniqueness(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	createTestUser(t, srv, "unique-email-1", "unique@example.com")

	// Same email, different account.
	_, err := srv.CreateUser(ctx, models.NewUser{
		Name:     "Imposter",
		Account:  "unique-email-2",
		Email:    "unique@example.com",
		Password: []byte("not-a-real-hash"),
	}, nil)
	if !errors.Is(err, ErrDBDuplicatedEntry) {
		t.Fatalf("duplicate email accepted; want ErrDBDuplicatedEntry, got %v", err)
	}

	// Case-variant email, different account: the index is on lower(email).
	_, err = srv.CreateUser(ctx, models.NewUser{
		Name:     "Imposter",
		Account:  "unique-email-3",
		Email:    "UNIQUE@example.com",
		Password: []byte("not-a-real-hash"),
	}, nil)
	if !errors.Is(err, ErrDBDuplicatedEntry) {
		t.Fatalf("case-variant duplicate email accepted; want ErrDBDuplicatedEntry, got %v", err)
	}
}

func TestAccountUniqueness(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	createTestUser(t, srv, "unique-account", "account-1@example.com")

	// Same account, different email.
	_, err := srv.CreateUser(ctx, models.NewUser{
		Name:     "Imposter",
		Account:  "unique-account",
		Email:    "account-2@example.com",
		Password: []byte("not-a-real-hash"),
	}, nil)
	if !errors.Is(err, ErrDBDuplicatedEntry) {
		t.Fatalf("duplicate account accepted; want ErrDBDuplicatedEntry, got %v", err)
	}
}

func TestRefreshTokenLifecycle(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "refresh-user", "refresh@example.com")
	plaintext := []byte("refresh-token-plaintext-value")

	created, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     plaintext,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateRefreshToken returned error: %v", err)
	}

	// Lookup is by plaintext; storage is the SHA-256 hash.
	fetched, err := srv.GetRefreshTokenByToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("GetRefreshTokenByToken returned error: %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("fetched wrong token: %s != %s", fetched.ID, created.ID)
	}
	if string(fetched.Token) == string(plaintext) {
		t.Error("token stored in plaintext; expected only the hash at rest")
	}
	if fetched.RevokedAt != nil {
		t.Error("new token must not be revoked")
	}

	if err := srv.RevokeRefreshToken(ctx, created.ID); err != nil {
		t.Fatalf("RevokeRefreshToken returned error: %v", err)
	}
	revoked, err := srv.GetRefreshTokenByToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("GetRefreshTokenByToken after revoke returned error: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after revocation")
	}

	if err := srv.DeleteRefreshTokensByUserID(ctx, user.ID); err != nil {
		t.Fatalf("DeleteRefreshTokensByUserID returned error: %v", err)
	}
	if _, err := srv.GetRefreshTokenByToken(ctx, plaintext); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("expected ErrDBNotFound after deletion, got %v", err)
	}

	// Foreign key: tokens cannot reference nonexistent users.
	_, err = srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    "999999",
		Token:     []byte("orphan"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if !errors.Is(err, ErrForeignKeyViolation) {
		t.Errorf("expected ErrForeignKeyViolation for unknown user, got %v", err)
	}
}

// TestRefreshTokenHashUniqueness verifies the storage backstop from migration
// 000008: two rows may never share a token hash, otherwise revoked-token
// replay becomes possible (lookup returns an arbitrary row of the pair).
func TestRefreshTokenHashUniqueness(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "unique-token-user", "unique-token@example.com")
	token := []byte("identical-refresh-token")

	if _, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken returned error: %v", err)
	}

	_, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if !errors.Is(err, ErrDBDuplicatedEntry) {
		t.Fatalf("duplicate token hash accepted; want ErrDBDuplicatedEntry, got %v", err)
	}
}

func TestRotateRefreshToken(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()
	user := createTestUser(t, srv, "rotate-token-user", "rotate-token@example.com")

	currentPlaintext := []byte("current-refresh-token")
	current, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     currentPlaintext,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateRefreshToken returned error: %v", err)
	}

	replacementPlaintext := []byte("replacement-refresh-token")
	rotated, err := srv.RotateRefreshToken(ctx, current.ID, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     replacementPlaintext,
		ExpiresAt: time.Now().UTC().Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("RotateRefreshToken returned error: %v", err)
	}
	if rotated.UserID != user.ID {
		t.Fatalf("rotated token belongs to %s, want %s", rotated.UserID, user.ID)
	}

	old, err := srv.GetRefreshTokenByToken(ctx, currentPlaintext)
	if err != nil {
		t.Fatalf("GetRefreshTokenByToken(current) returned error: %v", err)
	}
	if old.RevokedAt == nil {
		t.Fatal("current token was not revoked")
	}
	if _, err := srv.GetRefreshTokenByToken(ctx, replacementPlaintext); err != nil {
		t.Fatalf("replacement token was not stored: %v", err)
	}

	// A second concurrent/replayed rotation loses the conditional update.
	_, err = srv.RotateRefreshToken(ctx, current.ID, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     []byte("second-replacement"),
		ExpiresAt: time.Now().UTC().Add(2 * time.Hour),
	})
	if !errors.Is(err, ErrDBNotFound) {
		t.Fatalf("rotated the same token twice; want ErrDBNotFound, got %v", err)
	}
}

func TestDeleteExpiredRefreshTokens(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "expired-user", "expired@example.com")

	expired := []byte("already-expired-token")
	if _, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     expired,
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken returned error: %v", err)
	}

	if err := srv.DeleteExpiredRefreshTokens(ctx); err != nil {
		t.Fatalf("DeleteExpiredRefreshTokens returned error: %v", err)
	}

	if _, err := srv.GetRefreshTokenByToken(ctx, expired); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("expected expired token to be deleted, got %v", err)
	}
}

func TestPasswordResetTokenLifecycle(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "reset-user", "reset@example.com")

	if _, err := srv.CreatePasswordResetToken(ctx, models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     "reset-token-plaintext",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreatePasswordResetToken returned error: %v", err)
	}

	consumed, err := srv.ConsumePasswordResetToken(ctx, "reset-token-plaintext")
	if err != nil {
		t.Fatalf("ConsumePasswordResetToken returned error: %v", err)
	}
	if consumed.UserID != user.ID {
		t.Errorf("consumed token belongs to wrong user: %s != %s", consumed.UserID, user.ID)
	}
	if consumed.UsedAt == nil {
		t.Error("expected UsedAt to be stamped on consumption")
	}
	if consumed.Token == "reset-token-plaintext" {
		t.Error("reset token stored in plaintext; expected only the hash at rest")
	}

	// Second redemption must fail: consumption is atomic.
	if _, err := srv.ConsumePasswordResetToken(ctx, "reset-token-plaintext"); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("token consumed twice; want ErrDBNotFound, got %v", err)
	}

	// Expired tokens must not be redeemable.
	if _, err := srv.CreatePasswordResetToken(ctx, models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     "expired-reset-token",
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreatePasswordResetToken returned error: %v", err)
	}
	if _, err := srv.ConsumePasswordResetToken(ctx, "expired-reset-token"); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("expired token redeemed; want ErrDBNotFound, got %v", err)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user := createTestUser(t, srv, "passwd-user", "passwd@example.com")

	if err := srv.UpdateUserPassword(ctx, user.ID, []byte("new-hash")); err != nil {
		t.Fatalf("UpdateUserPassword returned error: %v", err)
	}

	fetched, err := srv.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}
	if string(fetched.Password) != "new-hash" {
		t.Error("password was not updated")
	}

	if err := srv.UpdateUserPassword(ctx, "999999", []byte("x")); !errors.Is(err, ErrDBNotFound) {
		t.Errorf("expected ErrDBNotFound for unknown user, got %v", err)
	}
}

func TestResetPasswordIsAtomicAndRevokesSessions(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()
	user := createTestUser(t, srv, "atomic-reset-user", "atomic-reset@example.com")

	if _, err := srv.CreatePasswordResetToken(ctx, models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     "atomic-reset-token",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreatePasswordResetToken returned error: %v", err)
	}
	refreshPlaintext := []byte("reset-session-token")
	if _, err := srv.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    user.ID,
		Token:     refreshPlaintext,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken returned error: %v", err)
	}

	if err := srv.ResetPassword(ctx, "atomic-reset-token", []byte("new-reset-hash")); err != nil {
		t.Fatalf("ResetPassword returned error: %v", err)
	}
	fetched, err := srv.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}
	if string(fetched.Password) != "new-reset-hash" {
		t.Fatalf("password was not updated: %q", fetched.Password)
	}
	if _, err := srv.GetRefreshTokenByToken(ctx, refreshPlaintext); !errors.Is(err, ErrDBNotFound) {
		t.Fatalf("refresh sessions survived password reset: %v", err)
	}
	if err := srv.ResetPassword(ctx, "atomic-reset-token", []byte("another-hash")); !errors.Is(err, ErrDBNotFound) {
		t.Fatalf("reset token was reused; want ErrDBNotFound, got %v", err)
	}
}

// TestOutboxLifecycle covers the transactional outbox: an event written with
// its mutation, fetched by the relay, marked published, and reaped.
func TestOutboxLifecycle(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	user, err := srv.CreateUser(ctx, models.NewUser{
		Name:     "Outbox User",
		Account:  "outbox-user",
		Email:    "outbox@example.com",
		Password: []byte("not-a-real-hash"),
	}, func(u models.User) *models.OutboxMessage {
		return &models.OutboxMessage{
			Topic:   "iam.user.created",
			Key:     u.ID,
			Payload: map[string]string{"user_id": u.ID, "email": u.Email},
			Headers: map[string]string{"correlation_id": "test-corr-id"},
		}
	})
	if err != nil {
		t.Fatalf("CreateUser with outbox event returned error: %v", err)
	}

	rows, err := srv.FetchUnpublishedOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("FetchUnpublishedOutbox returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending outbox row, got %d", len(rows))
	}
	row := rows[0]
	if row.Topic != "iam.user.created" || row.Key != user.ID {
		t.Errorf("outbox row has wrong topic/key: %s/%s", row.Topic, row.Key)
	}
	if row.Headers["correlation_id"] != "test-corr-id" {
		t.Errorf("outbox headers did not round-trip: %v", row.Headers)
	}
	var payload map[string]string
	if err := json.Unmarshal(row.Payload, &payload); err != nil {
		t.Fatalf("unmarshaling outbox payload: %v", err)
	}
	if payload["email"] != "outbox@example.com" {
		t.Errorf("outbox payload did not round-trip: %v", payload)
	}

	if err := srv.MarkOutboxPublished(ctx, []int64{row.ID}); err != nil {
		t.Fatalf("MarkOutboxPublished returned error: %v", err)
	}
	rows, err = srv.FetchUnpublishedOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("FetchUnpublishedOutbox after mark returned error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 pending rows after publish, got %d", len(rows))
	}

	// Retention: a zero window reaps everything already published.
	if err := srv.DeletePublishedOutbox(ctx, 0); err != nil {
		t.Fatalf("DeletePublishedOutbox returned error: %v", err)
	}
}

// TestOutboxAtomicity verifies the core guarantee: when the mutation fails,
// no event row is left behind — the transaction rolls back as a unit.
func TestOutboxAtomicity(t *testing.T) {
	srv := mustNew(t)
	ctx := context.Background()

	createTestUser(t, srv, "atomic-user", "atomic@example.com")

	eventBuilt := false
	_, err := srv.CreateUser(ctx, models.NewUser{
		Name:     "Imposter",
		Account:  "atomic-user-2",
		Email:    "atomic@example.com", // duplicate → mutation fails
		Password: []byte("not-a-real-hash"),
	}, func(u models.User) *models.OutboxMessage {
		eventBuilt = true
		return &models.OutboxMessage{Topic: "iam.user.created", Key: u.ID, Payload: u}
	})
	if !errors.Is(err, ErrDBDuplicatedEntry) {
		t.Fatalf("expected ErrDBDuplicatedEntry, got %v", err)
	}
	if eventBuilt {
		t.Error("event callback ran for a failed mutation")
	}

	rows, err := srv.FetchUnpublishedOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("FetchUnpublishedOutbox returned error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("failed mutation left %d outbox row(s) behind", len(rows))
	}
}
