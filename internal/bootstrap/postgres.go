package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/spectremi/open-aspm/internal/catalog"
	"github.com/spectremi/open-aspm/internal/identity"
	"github.com/spectremi/open-aspm/internal/tenancy"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{db: db}, nil
}

func (store *PostgresStore) Initialize(ctx context.Context, spec installationSpec) error {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin operator bootstrap: %w", err)
	}
	defer tx.Rollback()

	var installationExists, stateExists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT
		  EXISTS (SELECT 1 FROM open_aspm.bootstrap_installations WHERE id = 'initial'),
		  EXISTS (SELECT 1 FROM open_aspm.workspaces)
		    OR EXISTS (SELECT 1 FROM open_aspm.principals)
		    OR EXISTS (SELECT 1 FROM open_aspm.applications)`,
	).Scan(&installationExists, &stateExists); err != nil {
		return fmt.Errorf("inspect bootstrap state: %w", err)
	}
	if installationExists {
		return ErrAlreadyInitialized
	}
	if stateExists {
		return ErrNotEmpty
	}

	principal := identity.BootstrapPrincipal{
		PrincipalID: spec.PrincipalID, WorkspaceID: spec.WorkspaceID,
		DisplayName: "Initial operator", CreatedAt: spec.CreatedAt,
	}
	if err := identity.CreateBootstrapPrincipal(ctx, tx, principal); err != nil {
		return err
	}
	workspace := tenancy.BootstrapWorkspace{
		WorkspaceID: spec.WorkspaceID, PrincipalID: spec.PrincipalID,
		RoleID: spec.RoleID, BindingID: spec.BindingID, RoleName: "Initial operator",
		Capabilities: spec.Capabilities, CreatedAt: spec.CreatedAt,
	}
	if err := tenancy.CreateBootstrapWorkspace(ctx, tx, workspace); err != nil {
		return err
	}
	if err := identity.CreateBootstrapServiceAccount(ctx, tx, principal); err != nil {
		return err
	}
	if err := catalog.CreateBootstrapApplication(
		ctx, tx, spec.WorkspaceID, spec.ApplicationID, spec.CreatedAt,
	); err != nil {
		return err
	}
	if err := identity.CreateBootstrapToken(ctx, tx, identity.BootstrapToken{
		ID: spec.TokenID, PrincipalID: spec.PrincipalID, WorkspaceID: spec.WorkspaceID,
		Prefix: spec.TokenPrefix, Verifier: spec.Verifier, VerifierKeyID: spec.KeyID,
		Capabilities: spec.Capabilities, CreatedAt: spec.CreatedAt, ExpiresAt: spec.TokenExpires,
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.bootstrap_installations (
			id, workspace_id, application_id, principal_id, role_id, created_at
		) VALUES ('initial', $1, $2, $3, $4, $5)`,
		spec.WorkspaceID, spec.ApplicationID, spec.PrincipalID, spec.RoleID, spec.CreatedAt,
	); err != nil {
		return fmt.Errorf("record operator bootstrap: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operator bootstrap: %w", err)
	}
	return nil
}

func (store *PostgresStore) RotateToken(ctx context.Context, spec rotationSpec) (Result, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Result{}, fmt.Errorf("begin bootstrap token rotation: %w", err)
	}
	defer tx.Rollback()
	result := Result{TokenID: spec.TokenID, Token: spec.Token}
	var effectiveAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT workspace_id, application_id, principal_id, clock_timestamp()
		FROM open_aspm.bootstrap_installations
		WHERE id = 'initial'
		FOR UPDATE`,
	).Scan(&result.WorkspaceID, &result.ApplicationID, &result.PrincipalID, &effectiveAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrNotInitialized
	}
	if err != nil {
		return Result{}, fmt.Errorf("read operator bootstrap: %w", err)
	}
	if !effectiveAt.Valid {
		return Result{}, errors.New("bootstrap rotation time is unavailable")
	}
	tokenTTL := spec.TokenExpires.Sub(spec.CreatedAt)
	result.TokenExpires = effectiveAt.Time.Add(tokenTTL)
	if err := identity.RotateBootstrapToken(ctx, tx, identity.BootstrapToken{
		ID: spec.TokenID, PrincipalID: result.PrincipalID, WorkspaceID: result.WorkspaceID,
		Prefix: spec.TokenPrefix, Verifier: spec.Verifier, VerifierKeyID: spec.KeyID,
		Capabilities: spec.Capabilities, CreatedAt: effectiveAt.Time, ExpiresAt: result.TokenExpires,
	}); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("commit bootstrap token rotation: %w", err)
	}
	return result, nil
}
