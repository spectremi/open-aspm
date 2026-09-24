//go:build integration

package bootstrap

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

	"github.com/spectremi/open-aspm/internal/authentication"
	"github.com/spectremi/open-aspm/internal/authorization"
	"github.com/spectremi/open-aspm/internal/database"
)

func TestPostgresOperatorBootstrapAndTokenRecovery(t *testing.T) {
	ctx, db := openBootstrapDatabase(t)
	key := []byte("integration-test-bootstrap-key-32-bytes-minimum")
	authenticationStore, err := authentication.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	tokenService, err := authentication.NewService(authenticationStore, authentication.Config{
		ActiveKeyID: "test-key", Keys: map[string][]byte{"test-key": key},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, tokenService, Config{TokenTTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	created, err := service.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if _, err := service.Initialize(ctx); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Initialize() error = %v, want ErrAlreadyInitialized", err)
	}
	subject, err := tokenService.Authenticate(ctx, created.Token)
	if err != nil || subject.TokenID != created.TokenID || subject.PrincipalID != created.PrincipalID ||
		subject.WorkspaceID != created.WorkspaceID {
		t.Fatalf("Authenticate(initial) = (%+v, %v)", subject, err)
	}
	authorizationStore, err := authorization.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authorization.NewService(authorizationStore)
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range initialCapabilities {
		applicationID := created.ApplicationID
		if capability == "catalog:repositories:create" {
			applicationID = ""
		}
		if err := authorizer.Authorize(ctx, authorization.Request{
			PrincipalID: created.PrincipalID, WorkspaceID: created.WorkspaceID,
			ApplicationID: applicationID, Capability: capability, TokenID: created.TokenID,
		}); err != nil {
			t.Errorf("Authorize(%q) error = %v", capability, err)
		}
	}

	replacement, err := service.RotateToken(ctx)
	if err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}
	if replacement.WorkspaceID != created.WorkspaceID || replacement.ApplicationID != created.ApplicationID ||
		replacement.PrincipalID != created.PrincipalID || replacement.TokenID == created.TokenID ||
		replacement.Token == created.Token {
		t.Fatal("replacement did not preserve installation identity or rotate token identity")
	}
	if _, err := tokenService.Authenticate(ctx, created.Token); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("old Authenticate() error = %v, want ErrUnauthenticated", err)
	}
	if _, err := tokenService.Authenticate(ctx, replacement.Token); err != nil {
		t.Fatalf("replacement Authenticate() error = %v", err)
	}
	var active, revoked int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE revoked_at IS NULL),
		       count(*) FILTER (WHERE revoked_at IS NOT NULL)
		FROM open_aspm.api_tokens
		WHERE workspace_id = $1 AND principal_id = $2`,
		created.WorkspaceID, created.PrincipalID,
	).Scan(&active, &revoked); err != nil {
		t.Fatal(err)
	}
	if active != 1 || revoked != 1 {
		t.Fatalf("token counts = active %d, revoked %d", active, revoked)
	}
}

func TestPostgresBootstrapRejectsUntrackedState(t *testing.T) {
	ctx, db := openBootstrapDatabase(t)
	if _, err := db.ExecContext(ctx, `INSERT INTO open_aspm.workspaces (id) VALUES ('existing-workspace')`); err != nil {
		t.Fatal(err)
	}
	key := []byte("integration-test-bootstrap-key-32-bytes-minimum")
	authenticationStore, _ := authentication.NewPostgresStore(db)
	tokenService, _ := authentication.NewService(authenticationStore, authentication.Config{
		ActiveKeyID: "test-key", Keys: map[string][]byte{"test-key": key},
	})
	store, _ := NewPostgresStore(db)
	service, _ := NewService(store, tokenService, Config{TokenTTL: 30 * 24 * time.Hour})
	if _, err := service.Initialize(ctx); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("Initialize() error = %v, want ErrNotEmpty", err)
	}
	if _, err := service.RotateToken(ctx); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("RotateToken() error = %v, want ErrNotInitialized", err)
	}
}

func openBootstrapDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	adminURL := os.Getenv("OPEN_ASPM_TEST_DATABASE_ADMIN_URL")
	if adminURL == "" {
		t.Skip("OPEN_ASPM_TEST_DATABASE_ADMIN_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	databaseName := "open_aspm_bootstrap_" + suffix
	ownerRole := "open_aspm_bootstrap_owner_" + suffix
	password := "integration-test-only"
	databaseIdentifier := pgx.Identifier{databaseName}.Sanitize()
	ownerIdentifier := pgx.Identifier{ownerRole}.Sanitize()
	if _, err := admin.ExecContext(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'integration-test-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION",
		ownerIdentifier,
	)); err != nil {
		t.Fatalf("create test role: %v", err)
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
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ownerIdentifier))
	})
	databaseURL := bootstrapTestDatabaseURL(t, adminURL, databaseName, ownerRole, password)
	migrator, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := database.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return ctx, db
}

func bootstrapTestDatabaseURL(t *testing.T, baseURL, databaseName, user, password string) string {
	t.Helper()
	config, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.Path = "/" + databaseName
	config.User = url.UserPassword(user, password)
	return config.String()
}
