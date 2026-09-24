package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
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

func (store *PostgresStore) CreateRepository(
	ctx context.Context,
	spec createSpec,
) (RepositoryResult, error) {
	if !validOpaqueID(spec.Repository.ID) || !validOpaqueID(spec.Repository.WorkspaceID) ||
		!validOpaqueID(spec.Repository.CreatedByPrincipalID) || !validDisplayName(spec.Repository.DisplayName) ||
		spec.Repository.CreatedAt.IsZero() || spec.Repository.UpdatedAt.Before(spec.Repository.CreatedAt) ||
		spec.PrincipalID != spec.Repository.CreatedByPrincipalID || spec.APIMajorVersion != apiMajorVersion ||
		spec.Operation != operationCreateRepository || !idempotencyKeyPattern.MatchString(spec.IdempotencyKey) ||
		spec.IdempotencyExpires.Before(spec.Repository.CreatedAt.Add(minimumIdempotencyRetention)) {
		return RepositoryResult{}, ErrInvalid
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("begin repository creation: %w", err)
	}
	defer tx.Rollback()

	var workspaceExists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM open_aspm.workspaces WHERE id = $1)`,
		spec.Repository.WorkspaceID,
	).Scan(&workspaceExists); err != nil {
		return RepositoryResult{}, fmt.Errorf("resolve repository workspace: %w", err)
	}
	if !workspaceExists {
		return RepositoryResult{}, ErrWorkspaceNotFound
	}
	var lockAcquired bool
	if err := tx.QueryRowContext(ctx,
		`SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))`,
		"open-aspm-repository-idempotency:"+createLockKey(spec),
	).Scan(&lockAcquired); err != nil {
		return RepositoryResult{}, fmt.Errorf("lock repository idempotency scope: %w", err)
	}
	if !lockAcquired {
		return RepositoryResult{}, ErrIdempotencyInProgress
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.repository_create_idempotency (
			workspace_id, principal_id, api_major_version, operation,
			idempotency_key, request_fingerprint, repository_id, completed_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (
			workspace_id, principal_id, api_major_version, operation, idempotency_key
		) DO NOTHING`,
		spec.Repository.WorkspaceID, spec.PrincipalID, spec.APIMajorVersion, spec.Operation,
		spec.IdempotencyKey, spec.RequestFingerprint[:], spec.Repository.ID,
		spec.Repository.CreatedAt, spec.IdempotencyExpires,
	)
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("claim repository idempotency key: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("read repository idempotency result: %w", err)
	}
	if rows == 0 {
		replayed, fingerprint, err := selectRepositoryReplay(ctx, tx, spec)
		if err != nil {
			return RepositoryResult{}, err
		}
		if !bytes.Equal(fingerprint, spec.RequestFingerprint[:]) {
			return RepositoryResult{}, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return RepositoryResult{}, fmt.Errorf("finish repository replay: %w", err)
		}
		replayed.Created = false
		return replayed, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.repositories (
			workspace_id, id, display_name, created_by_principal_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6)`,
		spec.Repository.WorkspaceID, spec.Repository.ID, spec.Repository.DisplayName,
		spec.Repository.CreatedByPrincipalID, spec.Repository.CreatedAt, spec.Repository.UpdatedAt,
	); err != nil {
		return RepositoryResult{}, fmt.Errorf("insert repository: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RepositoryResult{}, fmt.Errorf("commit repository creation: %w", err)
	}
	return RepositoryResult{Repository: spec.Repository, Created: true}, nil
}

func selectRepositoryReplay(
	ctx context.Context,
	tx *sql.Tx,
	spec createSpec,
) (RepositoryResult, []byte, error) {
	var repository Repository
	var fingerprint []byte
	err := tx.QueryRowContext(ctx, `
		SELECT idem.request_fingerprint, repository.id, repository.workspace_id,
		       repository.display_name, repository.created_by_principal_id,
		       repository.created_at, repository.updated_at
		FROM open_aspm.repository_create_idempotency AS idem
		JOIN open_aspm.repositories AS repository
		  ON repository.workspace_id = idem.workspace_id
		 AND repository.id = idem.repository_id
		WHERE idem.workspace_id = $1 AND idem.principal_id = $2
		  AND idem.api_major_version = $3 AND idem.operation = $4
		  AND idem.idempotency_key = $5`,
		spec.Repository.WorkspaceID, spec.PrincipalID, spec.APIMajorVersion,
		spec.Operation, spec.IdempotencyKey,
	).Scan(
		&fingerprint, &repository.ID, &repository.WorkspaceID, &repository.DisplayName,
		&repository.CreatedByPrincipalID, &repository.CreatedAt, &repository.UpdatedAt,
	)
	if err != nil {
		return RepositoryResult{}, nil, fmt.Errorf("read repository replay: %w", err)
	}
	return RepositoryResult{Repository: repository}, fingerprint, nil
}

func (store *PostgresStore) LinkRepository(
	ctx context.Context,
	spec linkSpec,
) (RelationshipResult, error) {
	relationship := spec.Relationship
	if !validOpaqueID(relationship.ID) || !validOpaqueID(relationship.WorkspaceID) ||
		!validOpaqueID(relationship.ApplicationID) || !validOpaqueID(relationship.RepositoryID) ||
		!validOpaqueID(relationship.LinkedByPrincipalID) || relationship.ValidFrom.IsZero() ||
		relationship.ValidUntil != nil {
		return RelationshipResult{}, ErrInvalid
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RelationshipResult{}, fmt.Errorf("begin application repository link: %w", err)
	}
	defer tx.Rollback()

	var applicationExists, repositoryExists bool
	err = tx.QueryRowContext(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1 FROM open_aspm.applications
		    WHERE workspace_id = $1 AND id = $2
		  ),
		  EXISTS (
		    SELECT 1 FROM open_aspm.repositories
		    WHERE workspace_id = $1 AND id = $3
		  )`,
		relationship.WorkspaceID, relationship.ApplicationID, relationship.RepositoryID,
	).Scan(&applicationExists, &repositoryExists)
	if err != nil {
		return RelationshipResult{}, fmt.Errorf("resolve application repository link: %w", err)
	}
	if !applicationExists || !repositoryExists {
		return RelationshipResult{}, ErrLinkTargetNotFound
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.application_repository_relationships (
			workspace_id, id, application_id, repository_id,
			linked_by_principal_id, valid_from, valid_until
		) VALUES ($1, $2, $3, $4, $5, $6, NULL)
		ON CONFLICT (workspace_id, application_id, repository_id)
		WHERE valid_until IS NULL DO NOTHING`,
		relationship.WorkspaceID, relationship.ID, relationship.ApplicationID,
		relationship.RepositoryID, relationship.LinkedByPrincipalID, relationship.ValidFrom,
	)
	if err != nil {
		return RelationshipResult{}, fmt.Errorf("insert application repository link: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return RelationshipResult{}, fmt.Errorf("read application repository link result: %w", err)
	}
	if rows == 0 {
		replayed, err := selectActiveRelationship(ctx, tx, relationship)
		if err != nil {
			return RelationshipResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return RelationshipResult{}, fmt.Errorf("finish application repository link replay: %w", err)
		}
		return RelationshipResult{Relationship: replayed}, nil
	}
	if err := tx.Commit(); err != nil {
		return RelationshipResult{}, fmt.Errorf("commit application repository link: %w", err)
	}
	return RelationshipResult{Relationship: relationship, Created: true}, nil
}

func selectActiveRelationship(
	ctx context.Context,
	tx *sql.Tx,
	requested ApplicationRepositoryRelationship,
) (ApplicationRepositoryRelationship, error) {
	var relationship ApplicationRepositoryRelationship
	var validUntil sql.NullTime
	err := tx.QueryRowContext(ctx, `
		SELECT id, workspace_id, application_id, repository_id,
		       linked_by_principal_id, valid_from, valid_until
		FROM open_aspm.application_repository_relationships
		WHERE workspace_id = $1 AND application_id = $2
		  AND repository_id = $3 AND valid_until IS NULL`,
		requested.WorkspaceID, requested.ApplicationID, requested.RepositoryID,
	).Scan(
		&relationship.ID, &relationship.WorkspaceID, &relationship.ApplicationID,
		&relationship.RepositoryID, &relationship.LinkedByPrincipalID,
		&relationship.ValidFrom, &validUntil,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ApplicationRepositoryRelationship{}, ErrLinkTargetNotFound
	}
	if err != nil {
		return ApplicationRepositoryRelationship{}, fmt.Errorf("read active application repository link: %w", err)
	}
	if validUntil.Valid {
		value := validUntil.Time
		relationship.ValidUntil = &value
	}
	return relationship, nil
}
