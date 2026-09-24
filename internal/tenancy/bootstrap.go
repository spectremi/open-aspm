// Package tenancy owns workspace membership, roles, and role bindings.
package tenancy

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

var ErrInvalid = errors.New("invalid tenancy input")

var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

type BootstrapWorkspace struct {
	WorkspaceID  string
	PrincipalID  string
	RoleID       string
	BindingID    string
	RoleName     string
	Capabilities []string
	CreatedAt    time.Time
}

func CreateBootstrapWorkspace(ctx context.Context, tx *sql.Tx, spec BootstrapWorkspace) error {
	if err := validateBootstrap(spec, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.workspaces (id, created_at) VALUES ($1, $2)`,
		spec.WorkspaceID, spec.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap workspace: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.workspace_memberships (
			workspace_id, principal_id, state, valid_from
		) VALUES ($1, $2, 'active', $3)`,
		spec.WorkspaceID, spec.PrincipalID, spec.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap membership: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.roles (workspace_id, id, name, created_at)
		VALUES ($1, $2, $3, $4)`,
		spec.WorkspaceID, spec.RoleID, spec.RoleName, spec.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap role: %w", err)
	}
	for _, capability := range spec.Capabilities {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO open_aspm.role_capabilities (workspace_id, role_id, capability)
			VALUES ($1, $2, $3)`, spec.WorkspaceID, spec.RoleID, capability); err != nil {
			return fmt.Errorf("insert bootstrap role capability: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.role_bindings (
			workspace_id, id, principal_id, role_id, scope_type,
			application_id, valid_from
		) VALUES ($1, $2, $3, $4, 'workspace', NULL, $5)`,
		spec.WorkspaceID, spec.BindingID, spec.PrincipalID, spec.RoleID, spec.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert bootstrap role binding: %w", err)
	}
	return nil
}

func validateBootstrap(spec BootstrapWorkspace, tx *sql.Tx) error {
	if tx == nil || !validOpaqueID(spec.WorkspaceID) || !validOpaqueID(spec.PrincipalID) ||
		!validOpaqueID(spec.RoleID) || !validOpaqueID(spec.BindingID) ||
		!validName(spec.RoleName) || spec.CreatedAt.IsZero() || len(spec.Capabilities) == 0 {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(spec.Capabilities))
	for _, capability := range spec.Capabilities {
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

func validName(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 1 && length <= 128 &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}
