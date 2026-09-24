package catalog

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCreateRepositoryAuthorizesAndBuildsStoreSpec(t *testing.T) {
	authorizer := &recordingAuthorizer{}
	store := &recordingStore{}
	service := newTestService(t, store, authorizer)
	fixedTime := time.Date(2026, time.September, 24, 12, 0, 0, 123456000, time.UTC)
	service.now = func() time.Time { return fixedTime }
	service.random = deterministicRandom

	result, err := service.CreateRepository(context.Background(), CreateRepositoryRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		IdempotencyKey: "repository-request-1", DisplayName: "example-service",
	})
	if err != nil {
		t.Fatalf("CreateRepository() error = %v", err)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0] != (AuthorizationRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		Capability: CapabilityRepositoriesCreate,
	}) {
		t.Fatalf("authorization requests = %+v", authorizer.requests)
	}
	if store.createCalls != 1 {
		t.Fatalf("create calls = %d, want one", store.createCalls)
	}
	if store.createSpec.Repository.ID != "repo_aebagbafaydqqcikbmga2dqpcaireeyu" {
		t.Fatalf("repository ID = %q", store.createSpec.Repository.ID)
	}
	if store.createSpec.Repository.DisplayName != "example-service" ||
		store.createSpec.Repository.CreatedByPrincipalID != "principal-a" ||
		!store.createSpec.Repository.CreatedAt.Equal(fixedTime) ||
		!store.createSpec.Repository.UpdatedAt.Equal(fixedTime) {
		t.Fatalf("repository spec = %+v", store.createSpec.Repository)
	}
	if store.createSpec.APIMajorVersion != 1 ||
		store.createSpec.Operation != operationCreateRepository ||
		store.createSpec.IdempotencyKey != "repository-request-1" ||
		!store.createSpec.IdempotencyExpires.Equal(fixedTime.Add(24*time.Hour)) {
		t.Fatalf("idempotency spec = %+v", store.createSpec)
	}
	if result != store.createResult {
		t.Fatalf("result = %+v, want %+v", result, store.createResult)
	}
}

func TestLinkRepositoryAuthorizesApplicationScopeAndBuildsRelationship(t *testing.T) {
	authorizer := &recordingAuthorizer{}
	store := &recordingStore{}
	service := newTestService(t, store, authorizer)
	fixedTime := time.Date(2026, time.September, 24, 12, 5, 0, 0, time.FixedZone("test", 2*60*60))
	service.now = func() time.Time { return fixedTime }
	service.random = deterministicRandom

	result, err := service.LinkRepository(context.Background(), LinkRepositoryRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		ApplicationID: "application-a", RepositoryID: "repository-a",
	})
	if err != nil {
		t.Fatalf("LinkRepository() error = %v", err)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0] != (AuthorizationRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		Capability: CapabilityApplicationRepositoriesLink,
	}) {
		t.Fatalf("authorization requests = %+v", authorizer.requests)
	}
	if store.linkCalls != 1 {
		t.Fatalf("link calls = %d, want one", store.linkCalls)
	}
	relationship := store.linkSpec.Relationship
	if relationship.ID != "rel_aebagbafaydqqcikbmga2dqpcaireeyu" ||
		relationship.WorkspaceID != "workspace-a" || relationship.ApplicationID != "application-a" ||
		relationship.RepositoryID != "repository-a" || relationship.LinkedByPrincipalID != "principal-a" ||
		!relationship.ValidFrom.Equal(fixedTime.UTC()) || relationship.ValidUntil != nil {
		t.Fatalf("relationship spec = %+v", relationship)
	}
	if result != store.linkResult {
		t.Fatalf("result = %+v, want %+v", result, store.linkResult)
	}
}

func TestCatalogServiceDenialAndValidationPerformNoWrites(t *testing.T) {
	denied := errors.New("denied")
	for _, test := range []struct {
		name       string
		authorizer *recordingAuthorizer
		invoke     func(*Service) error
		want       error
	}{
		{
			name: "invalid repository request", authorizer: &recordingAuthorizer{}, want: ErrInvalid,
			invoke: func(service *Service) error {
				_, err := service.CreateRepository(context.Background(), CreateRepositoryRequest{
					PrincipalID: "principal-a", WorkspaceID: "workspace-a",
					IdempotencyKey: "bad key", DisplayName: "example",
				})
				return err
			},
		},
		{
			name: "repository authorization denied", authorizer: &recordingAuthorizer{err: denied}, want: denied,
			invoke: func(service *Service) error {
				_, err := service.CreateRepository(context.Background(), validCreateRequest())
				return err
			},
		},
		{
			name: "invalid link request", authorizer: &recordingAuthorizer{}, want: ErrInvalid,
			invoke: func(service *Service) error {
				_, err := service.LinkRepository(context.Background(), LinkRepositoryRequest{
					PrincipalID: "principal-a", WorkspaceID: "workspace-a",
					ApplicationID: " application-a", RepositoryID: "repository-a",
				})
				return err
			},
		},
		{
			name: "link authorization denied", authorizer: &recordingAuthorizer{err: denied}, want: denied,
			invoke: func(service *Service) error {
				_, err := service.LinkRepository(context.Background(), validLinkRequest())
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingStore{}
			service := newTestService(t, store, test.authorizer)
			if err := test.invoke(service); !errors.Is(err, test.want) {
				t.Fatalf("operation error = %v, want %v", err, test.want)
			}
			if store.createCalls != 0 || store.linkCalls != 0 {
				t.Fatalf("store calls = create %d, link %d; want zero", store.createCalls, store.linkCalls)
			}
		})
	}
}

func TestCreateRepositoryFingerprintUsesOnlyValidatedRequestBody(t *testing.T) {
	request := validCreateRequest()
	first, err := fingerprintCreate(request)
	if err != nil {
		t.Fatal(err)
	}
	changedScope := request
	changedScope.PrincipalID = "principal-b"
	changedScope.WorkspaceID = "workspace-b"
	changedScope.IdempotencyKey = "another-key"
	second, err := fingerprintCreate(changedScope)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("idempotency scope changed the request-body fingerprint")
	}
	changedBody := request
	changedBody.DisplayName = "different-service"
	third, err := fingerprintCreate(changedBody)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("different display name produced the same request fingerprint")
	}
}

func TestNewServiceRejectsUnsafeConfiguration(t *testing.T) {
	validStore := &recordingStore{}
	validAuthorizer := &recordingAuthorizer{}
	for _, test := range []struct {
		name       string
		store      store
		authorizer Authorizer
		retention  time.Duration
	}{
		{name: "nil store", authorizer: validAuthorizer, retention: 24 * time.Hour},
		{name: "nil authorizer", store: validStore, retention: 24 * time.Hour},
		{name: "short retention", store: validStore, authorizer: validAuthorizer, retention: 24*time.Hour - time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewService(test.store, test.authorizer, Config{IdempotencyRetention: test.retention}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewService() error = %v, want ErrInvalid", err)
			}
		})
	}
}

type recordingAuthorizer struct {
	requests []AuthorizationRequest
	err      error
}

func (authorizer *recordingAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) error {
	authorizer.requests = append(authorizer.requests, request)
	return authorizer.err
}

type recordingStore struct {
	createCalls  int
	createSpec   createSpec
	createResult RepositoryResult
	createErr    error
	linkCalls    int
	linkSpec     linkSpec
	linkResult   RelationshipResult
	linkErr      error
}

func (store *recordingStore) CreateRepository(_ context.Context, spec createSpec) (RepositoryResult, error) {
	store.createCalls++
	store.createSpec = spec
	return store.createResult, store.createErr
}

func (store *recordingStore) LinkRepository(_ context.Context, spec linkSpec) (RelationshipResult, error) {
	store.linkCalls++
	store.linkSpec = spec
	return store.linkResult, store.linkErr
}

func newTestService(t *testing.T, store store, authorizer Authorizer) *Service {
	t.Helper()
	service, err := NewService(store, authorizer, Config{IdempotencyRetention: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validCreateRequest() CreateRepositoryRequest {
	return CreateRepositoryRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		IdempotencyKey: "repository-request-1", DisplayName: "example-service",
	}
}

func validLinkRequest() LinkRepositoryRequest {
	return LinkRepositoryRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		ApplicationID: "application-a", RepositoryID: "repository-a",
	}
}

func deterministicRandom(buffer []byte) error {
	for index := range buffer {
		buffer[index] = byte(index + 1)
	}
	return nil
}
