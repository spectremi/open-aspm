// Package identity owns principal, service-account, and API-token writes.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid = errors.New("invalid identity input")
)

var (
	capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
	prefixPattern     = regexp.MustCompile(`^oaspm_[a-z2-7]{20}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type BootstrapPrincipal struct {
	PrincipalID string
	WorkspaceID string
	DisplayName string
	CreatedAt   time.Time
}

type BootstrapToken struct {
	ID            string
	PrincipalID   string
	WorkspaceID   string
	Prefix        string
	Verifier      [32]byte
	VerifierKeyID string
	Capabilities  []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

func CreateBootstrapPrincipal(
	ctx context.Context,
	tx *sql.Tx,
	principal BootstrapPrincipal,
) error {
	if tx == nil || !validOpaqueID(principal.PrincipalID) ||
		!validOpaqueID(principal.WorkspaceID) || !validDisplayName(principal.DisplayName) ||
		principal.CreatedAt.IsZero() {
		return ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.principals (id, kind, state, created_at, updated_at)
		VALUES ($1, 'service_account', 'active', $2, $2)`,
		principal.PrincipalID, principal.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap principal: %w", err)
	}
	return nil
}

func CreateBootstrapServiceAccount(
	ctx context.Context,
	tx *sql.Tx,
	principal BootstrapPrincipal,
) error {
	if tx == nil || !validOpaqueID(principal.PrincipalID) ||
		!validOpaqueID(principal.WorkspaceID) || !validDisplayName(principal.DisplayName) ||
		principal.CreatedAt.IsZero() {
		return ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.service_accounts (
			workspace_id, principal_id, display_name, owner_principal_id,
			expires_at, created_at
		) VALUES ($1, $2, $3, NULL, NULL, $4)`,
		principal.WorkspaceID, principal.PrincipalID, principal.DisplayName, principal.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap service account: %w", err)
	}
	return nil
}

func CreateBootstrapToken(ctx context.Context, tx *sql.Tx, token BootstrapToken) error {
	if err := validateToken(tx, token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.api_tokens (
			workspace_id, id, principal_id, token_prefix, verifier,
			verifier_key_id, application_scope_mode, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'workspace', $7, $8)`,
		token.WorkspaceID, token.ID, token.PrincipalID, token.Prefix,
		token.Verifier[:], token.VerifierKeyID, token.CreatedAt, token.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap API token: %w", err)
	}
	for _, capability := range token.Capabilities {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.api_token_capabilities (
				workspace_id, token_id, capability
			) VALUES ($1, $2, $3)`, token.WorkspaceID, token.ID, capability); err != nil {
			return fmt.Errorf("insert bootstrap token capability: %w", err)
		}
	}
	return nil
}

func RotateBootstrapToken(ctx context.Context, tx *sql.Tx, token BootstrapToken) error {
	if err := validateToken(tx, token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE open_aspm.api_tokens
		SET revoked_at = $3
		WHERE workspace_id = $1 AND principal_id = $2 AND revoked_at IS NULL`,
		token.WorkspaceID, token.PrincipalID, token.CreatedAt,
	); err != nil {
		return fmt.Errorf("revoke previous bootstrap API tokens: %w", err)
	}
	return CreateBootstrapToken(ctx, tx, token)
}

func validateToken(tx *sql.Tx, token BootstrapToken) error {
	if tx == nil || !validOpaqueID(token.ID) || !validOpaqueID(token.PrincipalID) ||
		!validOpaqueID(token.WorkspaceID) || !prefixPattern.MatchString(token.Prefix) ||
		!keyIDPattern.MatchString(token.VerifierKeyID) || token.CreatedAt.IsZero() ||
		!token.ExpiresAt.After(token.CreatedAt) || len(token.Capabilities) == 0 {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(token.Capabilities))
	for _, capability := range token.Capabilities {
		if !capabilityPattern.MatchString(capability) {
			return ErrInvalid
		}
		if _, duplicate := seen[capability]; duplicate {
			return ErrInvalid
		}
		seen[capability] = struct{}{}
	}
	return nil
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
