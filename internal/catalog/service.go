package catalog

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
)

type AuthorizationRequest struct {
	PrincipalID   string
	WorkspaceID   string
	ApplicationID string
	Capability    string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type store interface {
	CreateRepository(context.Context, createSpec) (RepositoryResult, error)
	LinkRepository(context.Context, linkSpec) (RelationshipResult, error)
}

type Config struct {
	IdempotencyRetention time.Duration
}

type Service struct {
	store      store
	authorizer Authorizer
	config     Config
	now        func() time.Time
	random     func([]byte) error
}

func NewService(store store, authorizer Authorizer, config Config) (*Service, error) {
	if store == nil || authorizer == nil || config.IdempotencyRetention < minimumIdempotencyRetention {
		return nil, ErrInvalid
	}
	return &Service{
		store: store, authorizer: authorizer, config: config, now: time.Now,
		random: func(buffer []byte) error {
			_, err := rand.Read(buffer)
			return err
		},
	}, nil
}

func (service *Service) CreateRepository(
	ctx context.Context,
	request CreateRepositoryRequest,
) (RepositoryResult, error) {
	if err := validateCreateRequest(request); err != nil {
		return RepositoryResult{}, err
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		PrincipalID: request.PrincipalID, WorkspaceID: request.WorkspaceID,
		Capability: CapabilityRepositoriesCreate,
	}); err != nil {
		return RepositoryResult{}, fmt.Errorf("authorize repository creation: %w", err)
	}
	fingerprint, err := fingerprintCreate(request)
	if err != nil {
		return RepositoryResult{}, err
	}
	id, err := service.randomIdentifier("repo_")
	if err != nil {
		return RepositoryResult{}, err
	}
	now := service.timestamp()
	return service.store.CreateRepository(ctx, createSpec{
		Repository: Repository{
			ID: id, WorkspaceID: request.WorkspaceID, DisplayName: request.DisplayName,
			CreatedByPrincipalID: request.PrincipalID, CreatedAt: now, UpdatedAt: now,
		},
		PrincipalID: request.PrincipalID, APIMajorVersion: apiMajorVersion,
		Operation: operationCreateRepository, IdempotencyKey: request.IdempotencyKey,
		RequestFingerprint: fingerprint,
		IdempotencyExpires: now.Add(service.config.IdempotencyRetention),
	})
}

func (service *Service) LinkRepository(
	ctx context.Context,
	request LinkRepositoryRequest,
) (RelationshipResult, error) {
	if err := validateLinkRequest(request); err != nil {
		return RelationshipResult{}, err
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		PrincipalID: request.PrincipalID, WorkspaceID: request.WorkspaceID,
		ApplicationID: request.ApplicationID,
		Capability:    CapabilityApplicationRepositoriesLink,
	}); err != nil {
		return RelationshipResult{}, fmt.Errorf("authorize application repository link: %w", err)
	}
	id, err := service.randomIdentifier("rel_")
	if err != nil {
		return RelationshipResult{}, err
	}
	return service.store.LinkRepository(ctx, linkSpec{Relationship: ApplicationRepositoryRelationship{
		ID: id, WorkspaceID: request.WorkspaceID, ApplicationID: request.ApplicationID,
		RepositoryID: request.RepositoryID, LinkedByPrincipalID: request.PrincipalID,
		ValidFrom: service.timestamp(),
	}})
}

func (service *Service) randomIdentifier(prefix string) (string, error) {
	buffer := make([]byte, 20)
	if err := service.random(buffer); err != nil {
		return "", fmt.Errorf("generate catalog identifier: %w", err)
	}
	return encodeRandomID(prefix, buffer), nil
}

func (service *Service) timestamp() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}
