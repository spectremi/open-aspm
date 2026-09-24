//go:build integration

package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spectremi/open-aspm/internal/database"
)

func TestPostgresBearerAuthenticationAndRevocation(t *testing.T) {
	ctx, ownerDB, runtimeDB := openAuthenticationDatabase(t)
	key := []byte("integration-test-verifier-key-32-bytes-minimum")
	store, err := NewPostgresStore(runtimeDB)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, Config{ActiveKeyID: "test-key", Keys: map[string][]byte{"test-key": key}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	generated, err := service.Generate()
	if err != nil {
		t.Fatal(err)
	}
	seedAuthenticationToken(t, ctx, ownerDB, generated, now)

	subject, err := service.Authenticate(ctx, generated.Plaintext)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if subject != (Subject{TokenID: "token-a", PrincipalID: "principal-a", WorkspaceID: "workspace-a"}) {
		t.Fatalf("subject = %+v", subject)
	}
	var lastUsed time.Time
	if err := ownerDB.QueryRowContext(ctx, `
		SELECT last_used_at FROM open_aspm.api_tokens
		WHERE workspace_id = 'workspace-a' AND id = 'token-a'`,
	).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Equal(now) {
		t.Fatalf("last_used_at = %v, want %v", lastUsed, now)
	}

	if _, err := ownerDB.ExecContext(ctx, `
		UPDATE open_aspm.api_tokens SET revoked_at = $1
		WHERE workspace_id = 'workspace-a' AND id = 'token-a'`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := service.Authenticate(ctx, generated.Plaintext); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked Authenticate() error = %v, want ErrUnauthenticated", err)
	}
}

func openAuthenticationDatabase(t *testing.T) (context.Context, *sql.DB, *sql.DB) {
	t.Helper()
	adminURL := os.Getenv("OPEN_ASPM_TEST_DATABASE_ADMIN_URL")
	if adminURL == "" {
		t.Skip("OPEN_ASPM_TEST_DATABASE_ADMIN_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("connect to test PostgreSQL: %v", err)
	}

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	databaseName := "open_aspm_authentication_" + suffix
	ownerRole := "open_aspm_authentication_owner_" + suffix
	runtimeRole := "open_aspm_authentication_runtime_" + suffix
	password := "integration-test-only"
	databaseIdentifier := pgx.Identifier{databaseName}.Sanitize()
	ownerIdentifier := pgx.Identifier{ownerRole}.Sanitize()
	runtimeIdentifier := pgx.Identifier{runtimeRole}.Sanitize()
	for _, role := range []string{ownerIdentifier, runtimeIdentifier} {
		if _, err := admin.ExecContext(ctx, fmt.Sprintf(
			"CREATE ROLE %s LOGIN PASSWORD 'integration-test-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION",
			role,
		)); err != nil {
			t.Fatalf("create test role: %v", err)
		}
	}
	if _, err := admin.ExecContext(ctx, fmt.Sprintf(
		"CREATE DATABASE %s OWNER %s", databaseIdentifier, ownerIdentifier,
	)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", databaseIdentifier))
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP ROLE IF EXISTS %s", runtimeIdentifier))
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ownerIdentifier))
	})

	ownerURL := authenticationTestDatabaseURL(t, adminURL, databaseName, ownerRole, password)
	migrator, err := database.Open(ctx, ownerURL)
	if err != nil {
		t.Fatalf("open migrator: %v", err)
	}
	if _, _, err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close migrator: %v", err)
	}
	ownerDB, err := sql.Open("pgx", ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })
	for _, grant := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA open_aspm TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, UPDATE (last_used_at) ON open_aspm.api_tokens TO %s", runtimeIdentifier),
	} {
		if _, err := ownerDB.ExecContext(ctx, grant); err != nil {
			t.Fatalf("grant authentication runtime access: %v", err)
		}
	}
	runtimeDB, err := sql.Open("pgx", authenticationTestDatabaseURL(t, adminURL, databaseName, runtimeRole, password))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtimeDB.Close() })
	return ctx, ownerDB, runtimeDB
}

func seedAuthenticationToken(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	generated GeneratedToken,
	now time.Time,
) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO open_aspm.workspaces (id, created_at) VALUES ('workspace-a', $1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO open_aspm.principals (id, kind, state, created_at, updated_at)
		  VALUES ('principal-a', 'service_account', 'active', $1, $1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO open_aspm.workspace_memberships (
			workspace_id, principal_id, state, valid_from
		  ) VALUES ('workspace-a', 'principal-a', 'active', $1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO open_aspm.service_accounts (
			workspace_id, principal_id, display_name, created_at
		  ) VALUES ('workspace-a', 'principal-a', 'CI uploader', $1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO open_aspm.api_tokens (
			workspace_id, id, principal_id, token_prefix, verifier,
			verifier_key_id, application_scope_mode, created_at, expires_at
		  ) VALUES ('workspace-a', 'token-a', 'principal-a', $1, $2, $3, 'workspace', $4, $5)`,
			[]any{generated.Prefix, generated.Verifier[:], generated.VerifierKeyID, now.Add(-time.Hour), now.Add(time.Hour)}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func authenticationTestDatabaseURL(t *testing.T, baseURL, databaseName, user, password string) string {
	t.Helper()
	config, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.Path = "/" + databaseName
	config.User = url.UserPassword(user, password)
	return config.String()
}
