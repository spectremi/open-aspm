package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spectremi/open-aspm/internal/authentication"
)

func TestInitializeBuildsOneBoundedInstallation(t *testing.T) {
	store := &recordingStore{}
	tokens := &recordingTokenGenerator{token: authentication.GeneratedToken{
		Plaintext: "token-plaintext", Prefix: "oaspm_aaaaaaaaaaaaaaaaaaaa",
		VerifierKeyID: "key-1",
	}}
	service, err := NewService(store, tokens, Config{TokenTTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.FixedZone("test", 2*60*60))
	service.now = func() time.Time { return now }
	fill := byte(1)
	service.random = func(buffer []byte) error {
		for index := range buffer {
			buffer[index] = fill
		}
		fill++
		return nil
	}
	result, err := service.Initialize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Token != "token-plaintext" || result.WorkspaceID == "" || result.ApplicationID == "" ||
		result.PrincipalID == "" || result.TokenID == "" {
		t.Fatalf("Initialize() = %+v", result)
	}
	wantTime := now.UTC().Truncate(time.Microsecond)
	if !store.installation.CreatedAt.Equal(wantTime) ||
		!result.TokenExpires.Equal(wantTime.Add(30*24*time.Hour)) {
		t.Fatalf("bootstrap times = (%v, %v)", store.installation.CreatedAt, result.TokenExpires)
	}
	if len(store.installation.Capabilities) != len(initialCapabilities) {
		t.Fatalf("capabilities = %#v", store.installation.Capabilities)
	}
	store.installation.Capabilities[0] = "mutated"
	if initialCapabilities[0] == "mutated" {
		t.Fatal("bootstrap leaked mutable capability storage")
	}
}

func TestRotateTokenUsesStoredInstallationIdentity(t *testing.T) {
	store := &recordingStore{rotationResult: Result{
		WorkspaceID: "workspace-a", ApplicationID: "application-a", PrincipalID: "principal-a",
	}}
	tokens := &recordingTokenGenerator{token: authentication.GeneratedToken{
		Plaintext: "replacement", Prefix: "oaspm_bbbbbbbbbbbbbbbbbbbb", VerifierKeyID: "key-2",
	}}
	service, err := NewService(store, tokens, Config{TokenTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.random = func(buffer []byte) error {
		for index := range buffer {
			buffer[index] = 9
		}
		return nil
	}
	result, err := service.RotateToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Token != "replacement" || result.TokenID == "" ||
		result.WorkspaceID != "workspace-a" || result.PrincipalID != "principal-a" {
		t.Fatalf("RotateToken() = %+v", result)
	}
	if store.rotation.Token != "replacement" || !store.rotation.TokenExpires.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("rotation spec = %+v", store.rotation)
	}
}

func TestNewServiceRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		store  store
		tokens tokenGenerator
		ttl    time.Duration
	}{
		{tokens: &recordingTokenGenerator{}, ttl: 24 * time.Hour},
		{store: &recordingStore{}, ttl: 24 * time.Hour},
		{store: &recordingStore{}, tokens: &recordingTokenGenerator{}, ttl: time.Hour},
		{store: &recordingStore{}, tokens: &recordingTokenGenerator{}, ttl: 366 * 24 * time.Hour},
	}
	for _, test := range tests {
		if _, err := NewService(test.store, test.tokens, Config{TokenTTL: test.ttl}); !errors.Is(err, ErrInvalid) {
			t.Errorf("NewService() error = %v, want ErrInvalid", err)
		}
	}
}

type recordingStore struct {
	installation   installationSpec
	initializeErr  error
	rotation       rotationSpec
	rotationResult Result
	rotationErr    error
}

func (store *recordingStore) Initialize(_ context.Context, spec installationSpec) error {
	store.installation = spec
	return store.initializeErr
}

func (store *recordingStore) RotateToken(_ context.Context, spec rotationSpec) (Result, error) {
	store.rotation = spec
	result := store.rotationResult
	result.TokenID = spec.TokenID
	result.Token = spec.Token
	result.TokenExpires = spec.TokenExpires
	return result, store.rotationErr
}

type recordingTokenGenerator struct {
	token authentication.GeneratedToken
	err   error
}

func (generator *recordingTokenGenerator) Generate() (authentication.GeneratedToken, error) {
	return generator.token, generator.err
}
