package authentication

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndAuthenticate(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := &recordingStore{active: true}
	service, err := NewService(store, Config{ActiveKeyID: "key-1", Keys: map[string][]byte{"key-1": key}})
	if err != nil {
		t.Fatal(err)
	}
	fill := byte(0)
	service.random = func(buffer []byte) error {
		for index := range buffer {
			buffer[index] = fill
			fill++
		}
		return nil
	}
	now := time.Date(2026, 9, 24, 12, 0, 0, 987654321, time.UTC)
	service.now = func() time.Time { return now }

	generated, err := service.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !prefixPattern.MatchString(generated.Prefix) || !strings.HasPrefix(generated.Plaintext, generated.Prefix+".") {
		t.Fatalf("generated token has invalid format: prefix=%q", generated.Prefix)
	}
	_, encodedSecret, _ := strings.Cut(generated.Plaintext, ".")
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != secretBytes {
		t.Fatalf("generated secret = %d bytes, %v", len(secret), err)
	}
	if generated.Verifier != verifier(key, generated.Plaintext) || generated.VerifierKeyID != "key-1" {
		t.Fatal("generated verifier does not match the active key")
	}

	store.record = tokenRecord{
		ID: "token-a", PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		Prefix: generated.Prefix, Verifier: generated.Verifier,
		VerifierKeyID: generated.VerifierKeyID, ExpiresAt: now.Add(time.Hour),
	}
	subject, err := service.Authenticate(context.Background(), generated.Plaintext)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if subject != (Subject{TokenID: "token-a", PrincipalID: "principal-a", WorkspaceID: "workspace-a"}) {
		t.Fatalf("subject = %+v", subject)
	}
	if store.used != store.record || !store.usedAt.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("recorded use = (%+v, %v)", store.used, store.usedAt)
	}
}

func TestAuthenticateRejectsInvalidOrInactiveCredentials(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	valid := "oaspm_aaaaaaaaaaaaaaaaaaaa." + base64.RawURLEncoding.EncodeToString(make([]byte, secretBytes))
	validVerifier := verifier(key, valid)
	tests := []struct {
		name      string
		plaintext string
		store     recordingStore
	}{
		{name: "empty", plaintext: ""},
		{name: "whitespace", plaintext: " " + valid},
		{name: "short secret", plaintext: "oaspm_aaaaaaaaaaaaaaaaaaaa.c2hvcnQ"},
		{name: "unknown prefix", plaintext: valid, store: recordingStore{findErr: ErrUnauthenticated}},
		{name: "inactive after verification", plaintext: valid, store: recordingStore{
			record: tokenRecord{ID: "token-a", PrincipalID: "principal-a", WorkspaceID: "workspace-a",
				Prefix: "oaspm_aaaaaaaaaaaaaaaaaaaa", Verifier: validVerifier, VerifierKeyID: "key-1"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := test.store
			service, err := NewService(&store, Config{ActiveKeyID: "key-1", Keys: map[string][]byte{"key-1": key}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Authenticate(context.Background(), test.plaintext); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate() error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestAuthenticateRejectsTamperingBeforeRecordingUse(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	original := "oaspm_aaaaaaaaaaaaaaaaaaaa." + base64.RawURLEncoding.EncodeToString(make([]byte, secretBytes))
	tamperedSecret := make([]byte, secretBytes)
	tamperedSecret[len(tamperedSecret)-1] = 1
	tampered := "oaspm_aaaaaaaaaaaaaaaaaaaa." + base64.RawURLEncoding.EncodeToString(tamperedSecret)
	store := &recordingStore{active: true, record: tokenRecord{
		ID: "token-a", PrincipalID: "principal-a", WorkspaceID: "workspace-a",
		Prefix: "oaspm_aaaaaaaaaaaaaaaaaaaa", Verifier: verifier(key, original), VerifierKeyID: "key-1",
	}}
	service, err := NewService(store, Config{ActiveKeyID: "key-1", Keys: map[string][]byte{"key-1": key}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), tampered); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate() error = %v, want ErrUnauthenticated", err)
	}
	if store.recordUseCalls != 0 {
		t.Fatalf("RecordUse calls = %d, want zero", store.recordUseCalls)
	}
}

func TestNewServiceValidatesAndCopiesKeys(t *testing.T) {
	validKey := []byte("0123456789abcdef0123456789abcdef")
	tests := []Config{
		{},
		{ActiveKeyID: "missing", Keys: map[string][]byte{"other": validKey}},
		{ActiveKeyID: "bad key", Keys: map[string][]byte{"bad key": validKey}},
		{ActiveKeyID: "short", Keys: map[string][]byte{"short": []byte("too-short")}},
	}
	for _, config := range tests {
		if _, err := NewService(&recordingStore{}, config); !errors.Is(err, ErrInvalid) {
			t.Errorf("NewService(%+v) error = %v, want ErrInvalid", config, err)
		}
	}
	if _, err := NewService(nil, Config{ActiveKeyID: "key-1", Keys: map[string][]byte{"key-1": validKey}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewService(nil) error = %v, want ErrInvalid", err)
	}

	store := &recordingStore{active: true}
	service, err := NewService(store, Config{ActiveKeyID: "key-1", Keys: map[string][]byte{"key-1": validKey}})
	if err != nil {
		t.Fatal(err)
	}
	validKey[0] ^= 0xff
	generated, err := service.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if generated.Verifier == verifier(validKey, generated.Plaintext) {
		t.Fatal("service retained caller-owned verifier key memory")
	}
}

type recordingStore struct {
	record         tokenRecord
	findErr        error
	active         bool
	useErr         error
	used           tokenRecord
	usedAt         time.Time
	recordUseCalls int
}

func (store *recordingStore) FindByPrefix(_ context.Context, _ string) (tokenRecord, error) {
	return store.record, store.findErr
}

func (store *recordingStore) RecordUse(_ context.Context, record tokenRecord, usedAt time.Time) (bool, error) {
	store.recordUseCalls++
	store.used = record
	store.usedAt = usedAt
	return store.active, store.useErr
}
