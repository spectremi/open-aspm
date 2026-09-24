// Package catalog owns stable asset identities and their explicit
// relationships.
package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	CapabilityRepositoriesCreate          = "catalog:repositories:create"
	CapabilityApplicationRepositoriesLink = "catalog:application-repositories:link"
	apiMajorVersion                       = 1
	operationCreateRepository             = "catalog.repositories.create"
	minimumIdempotencyRetention           = 24 * time.Hour
)

var (
	ErrInvalid                  = errors.New("invalid catalog input")
	ErrIdempotencyConflict      = errors.New("idempotency key reused for a different request")
	ErrIdempotencyInProgress    = errors.New("idempotent request is already in progress")
	ErrWorkspaceNotFound        = errors.New("catalog workspace not found")
	ErrLinkTargetNotFound       = errors.New("catalog relationship target not found")
	ErrRepositoryTargetNotFound = errors.New("active repository target not found")
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type CreateRepositoryRequest struct {
	PrincipalID    string
	WorkspaceID    string
	IdempotencyKey string
	DisplayName    string
}

type Repository struct {
	ID                   string
	WorkspaceID          string
	DisplayName          string
	CreatedByPrincipalID string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type RepositoryResult struct {
	Repository Repository
	Created    bool
}

type LinkRepositoryRequest struct {
	PrincipalID   string
	WorkspaceID   string
	ApplicationID string
	RepositoryID  string
}

type ApplicationRepositoryRelationship struct {
	ID                  string
	WorkspaceID         string
	ApplicationID       string
	RepositoryID        string
	LinkedByPrincipalID string
	ValidFrom           time.Time
	ValidUntil          *time.Time
}

type RelationshipResult struct {
	Relationship ApplicationRepositoryRelationship
	Created      bool
}

// ResolveRepositoryTargetRequest identifies one repository attribution within
// an already-authorized application scope.
type ResolveRepositoryTargetRequest struct {
	WorkspaceID   string
	ApplicationID string
	RepositoryID  string
}

// ResolvedRepositoryTarget is the stable Catalog identity and relationship
// that were active when another server module accepted an attribution.
type ResolvedRepositoryTarget struct {
	WorkspaceID    string
	ApplicationID  string
	RepositoryID   string
	RelationshipID string
	ValidFrom      time.Time
	ResolvedAt     time.Time
}

// RepositoryTargetResolver is the read-only Catalog application boundary used
// after a caller has authorized the containing Application operation.
type RepositoryTargetResolver interface {
	ResolveActiveRepositoryTarget(context.Context, ResolveRepositoryTargetRequest) (ResolvedRepositoryTarget, error)
}

type createSpec struct {
	Repository         Repository
	PrincipalID        string
	APIMajorVersion    int
	Operation          string
	IdempotencyKey     string
	RequestFingerprint [sha256.Size]byte
	IdempotencyExpires time.Time
}

type linkSpec struct {
	Relationship ApplicationRepositoryRelationship
}

func validateCreateRequest(request CreateRepositoryRequest) error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.WorkspaceID) ||
		!idempotencyKeyPattern.MatchString(request.IdempotencyKey) ||
		!validDisplayName(request.DisplayName) {
		return ErrInvalid
	}
	return nil
}

func validateLinkRequest(request LinkRepositoryRequest) error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.WorkspaceID) ||
		!validOpaqueID(request.ApplicationID) || !validOpaqueID(request.RepositoryID) {
		return ErrInvalid
	}
	return nil
}

func fingerprintCreate(request CreateRepositoryRequest) ([sha256.Size]byte, error) {
	if err := validateCreateRequest(request); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		DisplayName string `json:"display_name"`
	}{DisplayName: request.DisplayName})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func createLockKey(spec createSpec) string {
	encoded, _ := json.Marshal(struct {
		WorkspaceID     string `json:"workspace_id"`
		PrincipalID     string `json:"principal_id"`
		APIMajorVersion int    `json:"api_major_version"`
		Operation       string `json:"operation"`
		IdempotencyKey  string `json:"idempotency_key"`
	}{
		WorkspaceID: spec.Repository.WorkspaceID, PrincipalID: spec.PrincipalID,
		APIMajorVersion: spec.APIMajorVersion, Operation: spec.Operation,
		IdempotencyKey: spec.IdempotencyKey,
	})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validOpaqueID(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 3 && length <= 128 &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}

func validDisplayName(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 1 && length <= 255 &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}

func encodeRandomID(prefix string, random []byte) string {
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random))
}
