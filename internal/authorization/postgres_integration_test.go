//go:build integration

package authorization

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

func TestPostgresAuthorizationIntersectsEveryScope(t *testing.T) {
	service := openAuthorizationService(t)
	tests := []struct {
		name    string
		request Request
		allowed bool
	}{
		{
			name: "workspace role and token allow workspace capability",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "catalog:repositories:create", TokenID: "token-workspace"},
			allowed: true,
		},
		{
			name: "workspace role and token allow application capability",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-b", TokenID: "token-workspace"},
			allowed: true,
		},
		{
			name: "explicit token allows listed application",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-explicit"},
			allowed: true,
		},
		{
			name: "explicit token denies another application",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-b", TokenID: "token-explicit"},
		},
		{
			name: "explicit token cannot authorize workspace operation",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", TokenID: "token-explicit"},
		},
		{
			name: "token capability can narrow role",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "catalog:repositories:create", ApplicationID: "application-a", TokenID: "token-explicit"},
		},
		{
			name: "application binding allows its application",
			request: Request{PrincipalID: "principal-application", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-application"},
			allowed: true,
		},
		{
			name: "application binding denies another application",
			request: Request{PrincipalID: "principal-application", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-b", TokenID: "token-application"},
		},
		{
			name: "application binding denies workspace operation",
			request: Request{PrincipalID: "principal-application", WorkspaceID: "workspace-a",
				Capability: "imports:create", TokenID: "token-application"},
		},
		{
			name: "trusted internal reauthorization uses current role",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-b"},
			allowed: true,
		},
		{
			name: "workspace boundary denies",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-b",
				Capability: "imports:create", ApplicationID: "application-other", TokenID: "token-workspace"},
		},
		{
			name: "unknown application denies",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-unknown", TokenID: "token-workspace"},
		},
		{
			name: "expired service account denies",
			request: Request{PrincipalID: "principal-expired", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-expired-service"},
		},
		{
			name: "suspended principal denies",
			request: Request{PrincipalID: "principal-suspended", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-suspended-principal"},
		},
		{
			name: "suspended membership denies",
			request: Request{PrincipalID: "principal-membership", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-suspended-membership"},
		},
		{
			name: "revoked token denies",
			request: Request{PrincipalID: "principal-revoked", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-revoked"},
		},
		{
			name: "unknown token denies",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-unknown"},
		},
		{
			name: "unknown capability denies",
			request: Request{PrincipalID: "principal-workspace", WorkspaceID: "workspace-a",
				Capability: "findings:delete", ApplicationID: "application-a", TokenID: "token-workspace"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.Authorize(context.Background(), test.request)
			if test.allowed && err != nil {
				t.Fatalf("Authorize() error = %v, want allowed", err)
			}
			if !test.allowed && !errors.Is(err, ErrDenied) {
				t.Fatalf("Authorize() error = %v, want ErrDenied", err)
			}
		})
	}
}

func openAuthorizationService(t *testing.T) *Service {
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
	databaseName := "open_aspm_authorization_" + suffix
	ownerRole := "open_aspm_authorization_owner_" + suffix
	runtimeRole := "open_aspm_authorization_runtime_" + suffix
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

	ownerURL := authorizationTestDatabaseURL(t, adminURL, databaseName, ownerRole, password)
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
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	seedAuthorizationState(t, ctx, ownerDB, now)
	for _, grant := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA open_aspm TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.principals TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.workspace_memberships TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.service_accounts TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.applications TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.role_bindings TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.role_capabilities TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.api_tokens TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.api_token_capabilities TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.api_token_application_scopes TO %s", runtimeIdentifier),
	} {
		if _, err := ownerDB.ExecContext(ctx, grant); err != nil {
			t.Fatalf("grant authorization runtime access: %v", err)
		}
	}

	runtimeDB, err := sql.Open("pgx", authorizationTestDatabaseURL(t, adminURL, databaseName, runtimeRole, password))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtimeDB.Close() })
	store, err := NewPostgresStore(runtimeDB)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return service
}

func seedAuthorizationState(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, workspace := range []string{"workspace-a", "workspace-b"} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_aspm.workspaces (id, created_at) VALUES ($1, $2)`, workspace, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, application := range []struct{ workspace, id string }{
		{"workspace-a", "application-a"}, {"workspace-a", "application-b"},
		{"workspace-b", "application-other"},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_aspm.applications (workspace_id, id, created_at) VALUES ($1, $2, $3)`, application.workspace, application.id, now); err != nil {
			t.Fatal(err)
		}
	}
	principals := []struct {
		id, state, membership string
		expires               time.Time
	}{
		{id: "principal-workspace", state: "active", membership: "active"},
		{id: "principal-application", state: "active", membership: "active"},
		{id: "principal-expired", state: "active", membership: "active", expires: now.Add(-time.Minute)},
		{id: "principal-suspended", state: "suspended", membership: "active"},
		{id: "principal-membership", state: "active", membership: "suspended"},
		{id: "principal-revoked", state: "active", membership: "active"},
	}
	for _, principal := range principals {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.principals (id, kind, state, created_at, updated_at)
			VALUES ($1, 'service_account', $2, $3, $3)`, principal.id, principal.state, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.workspace_memberships (
				workspace_id, principal_id, state, valid_from
			) VALUES ('workspace-a', $1, $2, $3)`, principal.id, principal.membership, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		var expires any
		if !principal.expires.IsZero() {
			expires = principal.expires
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.service_accounts (
				workspace_id, principal_id, display_name, expires_at, created_at
			) VALUES ('workspace-a', $1, $1, $2, $3)`, principal.id, expires, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []struct{ id, name string }{
		{"role-workspace", "Workspace ingestion"}, {"role-application", "Application ingestion"},
	} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.roles (workspace_id, id, name, created_at)
			VALUES ('workspace-a', $1, $2, $3)`, role.id, role.name, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for _, capability := range []string{"imports:create", "catalog:repositories:create"} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.role_capabilities (workspace_id, role_id, capability)
			VALUES ('workspace-a', 'role-workspace', $1)`, capability); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.role_capabilities (workspace_id, role_id, capability)
		VALUES ('workspace-a', 'role-application', 'imports:create')`); err != nil {
		t.Fatal(err)
	}
	for _, principal := range principals {
		roleID, scopeType, applicationID := "role-workspace", "workspace", any(nil)
		if principal.id == "principal-application" {
			roleID, scopeType, applicationID = "role-application", "application", "application-a"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.role_bindings (
				workspace_id, id, principal_id, role_id, scope_type,
				application_id, valid_from
			) VALUES ('workspace-a', $1, $2, $3, $4, $5, $6)`,
			"binding-"+principal.id, principal.id, roleID, scopeType, applicationID, now.Add(-time.Hour),
		); err != nil {
			t.Fatal(err)
		}
	}
	tokens := []struct {
		id, principal, prefix, scope string
		revoked                      bool
	}{
		{"token-workspace", "principal-workspace", "oaspm_aaaaaaaaaaaaaaaaaaaa", "workspace", false},
		{"token-explicit", "principal-workspace", "oaspm_bbbbbbbbbbbbbbbbbbbb", "explicit", false},
		{"token-application", "principal-application", "oaspm_cccccccccccccccccccc", "workspace", false},
		{"token-expired-service", "principal-expired", "oaspm_dddddddddddddddddddd", "workspace", false},
		{"token-suspended-principal", "principal-suspended", "oaspm_eeeeeeeeeeeeeeeeeeee", "workspace", false},
		{"token-suspended-membership", "principal-membership", "oaspm_ffffffffffffffffffff", "workspace", false},
		{"token-revoked", "principal-revoked", "oaspm_gggggggggggggggggggg", "workspace", true},
	}
	for _, token := range tokens {
		var revoked any
		if token.revoked {
			revoked = now.Add(-time.Minute)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.api_tokens (
				workspace_id, id, principal_id, token_prefix, verifier,
				verifier_key_id, application_scope_mode, created_at, expires_at, revoked_at
			) VALUES (
				'workspace-a', $1, $2, $3, decode(repeat('01', 32), 'hex'),
				'test-key', $4, $5, $6, $7
			)`, token.id, token.principal, token.prefix, token.scope,
			now.Add(-time.Hour), now.Add(time.Hour), revoked,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.api_token_capabilities (workspace_id, token_id, capability)
			VALUES ('workspace-a', $1, 'imports:create')`, token.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.api_token_capabilities (workspace_id, token_id, capability)
		VALUES ('workspace-a', 'token-workspace', 'catalog:repositories:create')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.api_token_application_scopes (workspace_id, token_id, application_id)
		VALUES ('workspace-a', 'token-explicit', 'application-a')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func authorizationTestDatabaseURL(t *testing.T, baseURL, databaseName, user, password string) string {
	t.Helper()
	config, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.Path = "/" + databaseName
	config.User = url.UserPassword(user, password)
	return config.String()
}
