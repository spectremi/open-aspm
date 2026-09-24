// Package authentication verifies bearer credentials and returns authenticated
// principal identity without making authorization decisions.
package authentication

import (
	"errors"
	"regexp"
	"time"
)

const (
	prefixRandomBytes = 12
	secretBytes       = 32
	minimumKeyBytes   = 32
)

var (
	ErrInvalid         = errors.New("invalid authentication configuration")
	ErrUnauthenticated = errors.New("bearer token is invalid or inactive")
)

var (
	keyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	prefixPattern = regexp.MustCompile(`^oaspm_[a-z2-7]{20}$`)
)

// Config contains verifier keys. ActiveKeyID selects the key used for new
// tokens; retained keys permit bounded rotation of existing verifiers.
type Config struct {
	ActiveKeyID string
	Keys        map[string][]byte
}

// Subject is the authenticated token and principal identity. It is not an
// authorization decision; callers must still evaluate current role and token
// scopes for every protected operation.
type Subject struct {
	TokenID     string
	PrincipalID string
	WorkspaceID string
}

// GeneratedToken contains the plaintext credential exactly once plus the
// non-retrievable verifier material that may be persisted.
type GeneratedToken struct {
	Plaintext     string
	Prefix        string
	Verifier      [32]byte
	VerifierKeyID string
}

type tokenRecord struct {
	ID            string
	PrincipalID   string
	WorkspaceID   string
	Prefix        string
	Verifier      [32]byte
	VerifierKeyID string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

func validateConfig(config Config) error {
	if !keyIDPattern.MatchString(config.ActiveKeyID) || len(config.Keys) == 0 {
		return ErrInvalid
	}
	for keyID, key := range config.Keys {
		if !keyIDPattern.MatchString(keyID) || len(key) < minimumKeyBytes {
			return ErrInvalid
		}
	}
	if _, ok := config.Keys[config.ActiveKeyID]; !ok {
		return ErrInvalid
	}
	return nil
}
