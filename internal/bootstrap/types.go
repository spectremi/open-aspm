// Package bootstrap coordinates the one-time operator installation workflow
// while delegating domain writes to their owning modules.
package bootstrap

import (
	"errors"
	"time"

	"github.com/spectremi/open-aspm/internal/authentication"
)

const (
	initialInstallationID = "initial"
	minimumTokenTTL       = 24 * time.Hour
	maximumTokenTTL       = 365 * 24 * time.Hour
)

var (
	ErrAlreadyInitialized = errors.New("Open ASPM is already initialized")
	ErrInvalid            = errors.New("invalid bootstrap input")
	ErrNotInitialized     = errors.New("Open ASPM is not initialized")
	ErrNotEmpty           = errors.New("database contains untracked bootstrap state")
)

var initialCapabilities = []string{
	"catalog:application-repositories:link",
	"catalog:repositories:create",
	"imports:create",
	"imports:read-own",
	"imports:upload",
}

type Config struct {
	TokenTTL time.Duration
}

type Result struct {
	WorkspaceID   string
	ApplicationID string
	PrincipalID   string
	TokenID       string
	Token         string
	TokenExpires  time.Time
}

type installationSpec struct {
	Result
	RoleID       string
	BindingID    string
	TokenPrefix  string
	Verifier     [32]byte
	KeyID        string
	CreatedAt    time.Time
	Capabilities []string
}

type rotationSpec struct {
	TokenID      string
	Token        string
	TokenPrefix  string
	Verifier     [32]byte
	KeyID        string
	CreatedAt    time.Time
	TokenExpires time.Time
	Capabilities []string
}

type tokenGenerator interface {
	Generate() (authentication.GeneratedToken, error)
}
