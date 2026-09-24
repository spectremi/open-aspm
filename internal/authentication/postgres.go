package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
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

func (store *PostgresStore) FindByPrefix(ctx context.Context, prefix string) (tokenRecord, error) {
	if !prefixPattern.MatchString(prefix) {
		return tokenRecord{}, ErrUnauthenticated
	}
	var record tokenRecord
	var verifierBytes []byte
	var revokedAt sql.NullTime
	err := store.db.QueryRowContext(ctx, `
		SELECT id, principal_id, workspace_id, token_prefix, verifier,
		       verifier_key_id, expires_at, revoked_at
		FROM open_aspm.api_tokens
		WHERE token_prefix = $1`, prefix,
	).Scan(
		&record.ID, &record.PrincipalID, &record.WorkspaceID, &record.Prefix,
		&verifierBytes, &record.VerifierKeyID, &record.ExpiresAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenRecord{}, ErrUnauthenticated
	}
	if err != nil {
		return tokenRecord{}, fmt.Errorf("query API token: %w", err)
	}
	if len(verifierBytes) != len(record.Verifier) {
		return tokenRecord{}, errors.New("stored API token verifier has invalid length")
	}
	copy(record.Verifier[:], verifierBytes)
	if revokedAt.Valid {
		value := revokedAt.Time
		record.RevokedAt = &value
	}
	return record, nil
}

func (store *PostgresStore) RecordUse(
	ctx context.Context,
	record tokenRecord,
	usedAt time.Time,
) (bool, error) {
	if !prefixPattern.MatchString(record.Prefix) || record.ID == "" ||
		record.PrincipalID == "" || record.WorkspaceID == "" || usedAt.IsZero() {
		return false, ErrInvalid
	}
	result, err := store.db.ExecContext(ctx, `
		UPDATE open_aspm.api_tokens
		SET last_used_at = GREATEST(COALESCE(last_used_at, $5), $5)
		WHERE workspace_id = $1 AND id = $2 AND principal_id = $3
		  AND token_prefix = $4 AND created_at <= $5
		  AND expires_at > $5 AND revoked_at IS NULL`,
		record.WorkspaceID, record.ID, record.PrincipalID, record.Prefix, usedAt,
	)
	if err != nil {
		return false, fmt.Errorf("update API token use: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read API token use result: %w", err)
	}
	return rows == 1, nil
}
