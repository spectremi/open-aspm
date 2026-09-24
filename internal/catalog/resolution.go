package catalog

import (
	"context"
	"errors"
)

type resolutionStore interface {
	resolveActiveRepositoryTarget(context.Context, ResolveRepositoryTargetRequest) (ResolvedRepositoryTarget, error)
}

// ResolutionService exposes only the bounded Catalog lookup required by
// another authorized server application service. It does not grant general
// Catalog read access.
type ResolutionService struct {
	store resolutionStore
}

func NewResolutionService(store resolutionStore) (*ResolutionService, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &ResolutionService{store: store}, nil
}

func (service *ResolutionService) ResolveActiveRepositoryTarget(
	ctx context.Context,
	request ResolveRepositoryTargetRequest,
) (ResolvedRepositoryTarget, error) {
	if !validOpaqueID(request.WorkspaceID) || !validOpaqueID(request.ApplicationID) ||
		!validOpaqueID(request.RepositoryID) {
		return ResolvedRepositoryTarget{}, ErrInvalid
	}
	target, err := service.store.resolveActiveRepositoryTarget(ctx, request)
	if errors.Is(err, ErrLinkTargetNotFound) {
		return ResolvedRepositoryTarget{}, ErrRepositoryTargetNotFound
	}
	return target, err
}
