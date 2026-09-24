package catalog

import (
	"context"
	"errors"
	"testing"
)

func TestResolutionServiceReturnsOnlyActiveScopedTarget(t *testing.T) {
	store := &recordingResolutionStore{result: ResolvedRepositoryTarget{
		WorkspaceID: "workspace-a", ApplicationID: "application-a",
		RepositoryID: "repository-a", RelationshipID: "relationship-a",
	}}
	service, err := NewResolutionService(store)
	if err != nil {
		t.Fatal(err)
	}
	request := ResolveRepositoryTargetRequest{
		WorkspaceID: "workspace-a", ApplicationID: "application-a", RepositoryID: "repository-a",
	}
	result, err := service.ResolveActiveRepositoryTarget(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.request != request || result != store.result {
		t.Fatalf("resolution = (%+v, calls %d, request %+v)", result, store.calls, store.request)
	}
}

func TestResolutionServiceConcealsMissingRelationship(t *testing.T) {
	store := &recordingResolutionStore{err: ErrLinkTargetNotFound}
	service, err := NewResolutionService(store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ResolveActiveRepositoryTarget(context.Background(), ResolveRepositoryTargetRequest{
		WorkspaceID: "workspace-a", ApplicationID: "application-a", RepositoryID: "repository-a",
	})
	if !errors.Is(err, ErrRepositoryTargetNotFound) {
		t.Fatalf("ResolveActiveRepositoryTarget() error = %v, want ErrRepositoryTargetNotFound", err)
	}
}

func TestResolutionServiceRejectsInvalidInputWithoutStoreRead(t *testing.T) {
	store := &recordingResolutionStore{}
	service, err := NewResolutionService(store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ResolveActiveRepositoryTarget(context.Background(), ResolveRepositoryTargetRequest{
		WorkspaceID: "workspace-a", ApplicationID: "application-a", RepositoryID: " x",
	})
	if !errors.Is(err, ErrInvalid) || store.calls != 0 {
		t.Fatalf("resolution = error %v, calls %d; want ErrInvalid and no read", err, store.calls)
	}
	if _, err := NewResolutionService(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewResolutionService(nil) error = %v, want ErrInvalid", err)
	}
}

type recordingResolutionStore struct {
	calls   int
	request ResolveRepositoryTargetRequest
	result  ResolvedRepositoryTarget
	err     error
}

func (store *recordingResolutionStore) resolveActiveRepositoryTarget(
	_ context.Context,
	request ResolveRepositoryTargetRequest,
) (ResolvedRepositoryTarget, error) {
	store.calls++
	store.request = request
	return store.result, store.err
}
