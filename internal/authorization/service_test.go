package authorization

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceAllowsAndDeniesStoreDecision(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.FixedZone("test", 2*60*60))
	store := &recordingStore{allowed: true}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	request := validRequest()
	if err := service.Authorize(context.Background(), request); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if store.spec.Request != request {
		t.Fatalf("stored request = %+v, want %+v", store.spec.Request, request)
	}
	wantTime := now.UTC().Truncate(time.Microsecond)
	if !store.spec.EvaluatedAt.Equal(wantTime) {
		t.Fatalf("evaluation time = %v, want %v", store.spec.EvaluatedAt, wantTime)
	}

	store.allowed = false
	if err := service.Authorize(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied Authorize() error = %v, want ErrDenied", err)
	}
}

func TestServiceFailsClosed(t *testing.T) {
	backendErr := errors.New("database unavailable")
	store := &recordingStore{err: backendErr}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	err = service.Authorize(context.Background(), validRequest())
	if !errors.Is(err, backendErr) || errors.Is(err, ErrDenied) {
		t.Fatalf("Authorize() error = %v, want wrapped backend error", err)
	}
}

func TestServiceRejectsInvalidRequestsBeforeStore(t *testing.T) {
	store := &recordingStore{allowed: true}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	tests := []Request{
		{},
		{PrincipalID: "p", WorkspaceID: "workspace-a", Capability: "imports:create"},
		{PrincipalID: "principal-a", WorkspaceID: "workspace-a", Capability: "Imports Create"},
		{PrincipalID: "principal-a", WorkspaceID: "workspace-a", Capability: "imports:create", ApplicationID: "x"},
		{PrincipalID: "principal-a", WorkspaceID: "workspace-a", Capability: "imports:create", TokenID: " token-a"},
	}
	for _, request := range tests {
		if err := service.Authorize(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Errorf("Authorize(%+v) error = %v, want ErrInvalid", request, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want zero", store.calls)
	}
}

func TestNewServiceRejectsNilStore(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewService(nil) error = %v, want ErrInvalid", err)
	}
}

type recordingStore struct {
	allowed bool
	err     error
	spec    decisionSpec
	calls   int
}

func (store *recordingStore) IsAllowed(_ context.Context, spec decisionSpec) (bool, error) {
	store.calls++
	store.spec = spec
	return store.allowed, store.err
}

func validRequest() Request {
	return Request{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		Capability: "imports:create", ApplicationID: "application-a", TokenID: "token-a",
	}
}
