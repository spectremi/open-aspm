//go:build integration

package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spectremi/open-aspm/internal/database"
)

func TestPostgresRepositoryCreationIdempotencyAndIsolation(t *testing.T) {
	service, db := openCatalogService(t)
	ctx := context.Background()
	request := validCreateRequest()

	created, err := service.CreateRepository(ctx, request)
	if err != nil || !created.Created {
		t.Fatalf("first CreateRepository() = (%+v, %v), want created", created, err)
	}
	replayed, err := service.CreateRepository(ctx, request)
	if err != nil || replayed.Created || replayed.Repository.ID != created.Repository.ID {
		t.Fatalf("replayed CreateRepository() = (%+v, %v)", replayed, err)
	}

	sameName := request
	sameName.IdempotencyKey = "same-name-distinct-operation"
	distinct, err := service.CreateRepository(ctx, sameName)
	if err != nil || !distinct.Created || distinct.Repository.ID == created.Repository.ID {
		t.Fatalf("same-name CreateRepository() = (%+v, %v), want distinct repository", distinct, err)
	}
	conflict := request
	conflict.DisplayName = "different-service"
	if _, err := service.CreateRepository(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting CreateRepository() error = %v, want ErrIdempotencyConflict", err)
	}

	otherPrincipal := request
	otherPrincipal.PrincipalID = "principal-b"
	principalResult, err := service.CreateRepository(ctx, otherPrincipal)
	if err != nil || !principalResult.Created || principalResult.Repository.ID == created.Repository.ID {
		t.Fatalf("other-principal CreateRepository() = (%+v, %v)", principalResult, err)
	}
	otherWorkspace := request
	otherWorkspace.WorkspaceID = "workspace-b"
	workspaceResult, err := service.CreateRepository(ctx, otherWorkspace)
	if err != nil || !workspaceResult.Created || workspaceResult.Repository.ID == created.Repository.ID {
		t.Fatalf("other-workspace CreateRepository() = (%+v, %v)", workspaceResult, err)
	}
	missingWorkspace := request
	missingWorkspace.WorkspaceID = "workspace-missing"
	missingWorkspace.IdempotencyKey = "missing-workspace"
	if _, err := service.CreateRepository(ctx, missingWorkspace); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("missing-workspace CreateRepository() error = %v, want ErrWorkspaceNotFound", err)
	}

	var sameNameCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM open_aspm.repositories
		WHERE workspace_id = $1 AND display_name = $2`,
		request.WorkspaceID, request.DisplayName,
	).Scan(&sameNameCount); err != nil {
		t.Fatal(err)
	}
	if sameNameCount != 3 {
		t.Fatalf("same-name repository count = %d, want 3", sameNameCount)
	}
	var retentionSeconds int64
	if err := db.QueryRowContext(ctx, `
		SELECT extract(epoch FROM (expires_at - completed_at))::bigint
		FROM open_aspm.repository_create_idempotency
		WHERE workspace_id = $1 AND principal_id = $2 AND idempotency_key = $3`,
		request.WorkspaceID, request.PrincipalID, request.IdempotencyKey,
	).Scan(&retentionSeconds); err != nil {
		t.Fatal(err)
	}
	if retentionSeconds < int64((24*time.Hour)/time.Second) {
		t.Fatalf("idempotency retention = %ds, want at least 24h", retentionSeconds)
	}
}

func TestPostgresApplicationRepositoryLinkReplayConcurrencyAndIsolation(t *testing.T) {
	service, db := openCatalogService(t)
	ctx := context.Background()
	repository, err := service.CreateRepository(ctx, validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := validLinkRequest()
	request.RepositoryID = repository.Repository.ID

	created, err := service.LinkRepository(ctx, request)
	if err != nil || !created.Created {
		t.Fatalf("first LinkRepository() = (%+v, %v), want created", created, err)
	}
	replayed, err := service.LinkRepository(ctx, request)
	if err != nil || replayed.Created || replayed.Relationship.ID != created.Relationship.ID {
		t.Fatalf("replayed LinkRepository() = (%+v, %v)", replayed, err)
	}
	otherApplication := request
	otherApplication.ApplicationID = "application-other"
	otherLink, err := service.LinkRepository(ctx, otherApplication)
	if err != nil || !otherLink.Created || otherLink.Relationship.ID == created.Relationship.ID {
		t.Fatalf("other-application LinkRepository() = (%+v, %v)", otherLink, err)
	}

	otherWorkspaceCreate := validCreateRequest()
	otherWorkspaceCreate.WorkspaceID = "workspace-b"
	otherWorkspaceCreate.IdempotencyKey = "workspace-b-repository"
	otherWorkspaceRepository, err := service.CreateRepository(ctx, otherWorkspaceCreate)
	if err != nil {
		t.Fatal(err)
	}
	crossWorkspace := request
	crossWorkspace.RepositoryID = otherWorkspaceRepository.Repository.ID
	if _, err := service.LinkRepository(ctx, crossWorkspace); !errors.Is(err, ErrLinkTargetNotFound) {
		t.Fatalf("cross-workspace LinkRepository() error = %v, want ErrLinkTargetNotFound", err)
	}

	concurrent := request
	concurrent.ApplicationID = "application-concurrent"
	const callCount = 16
	type linkResult struct {
		result RelationshipResult
		err    error
	}
	results := make(chan linkResult, callCount)
	var wait sync.WaitGroup
	for index := 0; index < callCount; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.LinkRepository(ctx, concurrent)
			results <- linkResult{result: result, err: err}
		}()
	}
	wait.Wait()
	close(results)
	createdCount := 0
	var relationshipID string
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent LinkRepository() error = %v", result.err)
		}
		if relationshipID == "" {
			relationshipID = result.result.Relationship.ID
		} else if result.result.Relationship.ID != relationshipID {
			t.Fatalf("relationship ID = %q, want %q", result.result.Relationship.ID, relationshipID)
		}
		if result.result.Created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created concurrent links = %d, want one", createdCount)
	}
	var activeCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM open_aspm.application_repository_relationships
		WHERE workspace_id = $1 AND application_id = $2
		  AND repository_id = $3 AND valid_until IS NULL`,
		concurrent.WorkspaceID, concurrent.ApplicationID, concurrent.RepositoryID,
	).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("active relationship count = %d, want one", activeCount)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE open_aspm.repositories SET display_name = 'forbidden'
		WHERE workspace_id = $1 AND id = $2`, request.WorkspaceID, request.RepositoryID); err == nil {
		t.Fatal("runtime role unexpectedly updated a repository")
	}
	if _, err := db.ExecContext(ctx, `
		DELETE FROM open_aspm.application_repository_relationships
		WHERE workspace_id = $1 AND id = $2`, request.WorkspaceID, created.Relationship.ID); err == nil {
		t.Fatal("runtime role unexpectedly deleted a relationship")
	}
}

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, AuthorizationRequest) error { return nil }

func openCatalogService(t *testing.T) (*Service, *sql.DB) {
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
	databaseName := "open_aspm_catalog_" + suffix
	ownerRole := "open_aspm_catalog_owner_" + suffix
	runtimeRole := "open_aspm_catalog_runtime_" + suffix
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

	ownerURL := catalogTestDatabaseURL(t, adminURL, databaseName, ownerRole, password)
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
	defer ownerDB.Close()
	for _, workspaceID := range []string{"workspace-a", "workspace-b"} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO open_aspm.workspaces (id) VALUES ($1)`, workspaceID); err != nil {
			t.Fatalf("create workspace: %v", err)
		}
	}
	for _, application := range []struct{ workspaceID, id string }{
		{workspaceID: "workspace-a", id: "application-a"},
		{workspaceID: "workspace-a", id: "application-other"},
		{workspaceID: "workspace-a", id: "application-concurrent"},
		{workspaceID: "workspace-b", id: "application-b"},
	} {
		if _, err := ownerDB.ExecContext(ctx, `
			INSERT INTO open_aspm.applications (workspace_id, id) VALUES ($1, $2)`,
			application.workspaceID, application.id,
		); err != nil {
			t.Fatalf("create application: %v", err)
		}
	}
	for _, grant := range []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA open_aspm TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.workspaces TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.applications TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.repositories TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.repository_create_idempotency TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.application_repository_relationships TO %s", runtimeIdentifier),
	} {
		if _, err := ownerDB.ExecContext(ctx, grant); err != nil {
			t.Fatalf("grant catalog runtime access: %v", err)
		}
	}

	runtimeURL := catalogTestDatabaseURL(t, adminURL, databaseName, runtimeRole, password)
	db, err := sql.Open("pgx", runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(20)
	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, allowAuthorizer{}, Config{IdempotencyRetention: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return service, db
}

func catalogTestDatabaseURL(t *testing.T, baseURL, databaseName, user, password string) string {
	t.Helper()
	config, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.Path = "/" + databaseName
	config.User = url.UserPassword(user, password)
	return config.String()
}
