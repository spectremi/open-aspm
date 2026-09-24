package authentication

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

type tokenStore interface {
	FindByPrefix(context.Context, string) (tokenRecord, error)
	RecordUse(context.Context, tokenRecord, time.Time) (bool, error)
}

// Service generates non-retrievable API-token material and authenticates a
// complete bearer token through its public prefix and keyed verifier.
type Service struct {
	store       tokenStore
	activeKeyID string
	keys        map[string][]byte
	now         func() time.Time
	random      func([]byte) error
}

func NewService(store tokenStore, config Config) (*Service, error) {
	if store == nil || validateConfig(config) != nil {
		return nil, ErrInvalid
	}
	keys := make(map[string][]byte, len(config.Keys))
	for keyID, key := range config.Keys {
		keys[keyID] = append([]byte(nil), key...)
	}
	return &Service{
		store: store, activeKeyID: config.ActiveKeyID, keys: keys, now: time.Now,
		random: func(buffer []byte) error {
			_, err := rand.Read(buffer)
			return err
		},
	}, nil
}

// Generate creates a credential with 256 bits of secret material. The caller
// persists only Prefix, Verifier, and VerifierKeyID and displays Plaintext once.
func (service *Service) Generate() (GeneratedToken, error) {
	prefixBytes := make([]byte, prefixRandomBytes)
	secret := make([]byte, secretBytes)
	if err := service.random(prefixBytes); err != nil {
		return GeneratedToken{}, fmt.Errorf("generate token prefix: %w", err)
	}
	if err := service.random(secret); err != nil {
		return GeneratedToken{}, fmt.Errorf("generate token secret: %w", err)
	}
	prefix := "oaspm_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(prefixBytes))
	plaintext := prefix + "." + base64.RawURLEncoding.EncodeToString(secret)
	return GeneratedToken{
		Plaintext: plaintext, Prefix: prefix,
		Verifier:      verifier(service.keys[service.activeKeyID], plaintext),
		VerifierKeyID: service.activeKeyID,
	}, nil
}

// Authenticate verifies the credential in constant time and atomically records
// successful use only while the token remains unexpired and unrevoked.
func (service *Service) Authenticate(ctx context.Context, plaintext string) (Subject, error) {
	prefix, ok := parseToken(plaintext)
	if !ok {
		return Subject{}, ErrUnauthenticated
	}
	record, err := service.store.FindByPrefix(ctx, prefix)
	if errors.Is(err, ErrUnauthenticated) {
		return Subject{}, ErrUnauthenticated
	}
	if err != nil {
		return Subject{}, fmt.Errorf("load bearer token: %w", err)
	}
	key, ok := service.keys[record.VerifierKeyID]
	if !ok {
		return Subject{}, errors.New("bearer token verifier key is unavailable")
	}
	candidate := verifier(key, plaintext)
	if !hmac.Equal(candidate[:], record.Verifier[:]) {
		return Subject{}, ErrUnauthenticated
	}
	usedAt := service.now().UTC().Truncate(time.Microsecond)
	active, err := service.store.RecordUse(ctx, record, usedAt)
	if err != nil {
		return Subject{}, fmt.Errorf("record bearer token use: %w", err)
	}
	if !active {
		return Subject{}, ErrUnauthenticated
	}
	return Subject{
		TokenID: record.ID, PrincipalID: record.PrincipalID, WorkspaceID: record.WorkspaceID,
	}, nil
}

func verifier(key []byte, plaintext string) [sha256.Size]byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(plaintext))
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func parseToken(plaintext string) (string, bool) {
	if len(plaintext) != len("oaspm_")+20+1+43 || strings.TrimSpace(plaintext) != plaintext {
		return "", false
	}
	prefix, encodedSecret, found := strings.Cut(plaintext, ".")
	if !found || !prefixPattern.MatchString(prefix) {
		return "", false
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != secretBytes {
		return "", false
	}
	return prefix, true
}
