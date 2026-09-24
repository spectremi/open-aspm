package correlation

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PostgresStore owns writes to correlation outcome tables.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{db: db}, nil
}

// RecordUncorrelated immutably records why one algorithm version could not
// correlate an Observation. Exact replay returns the retained outcome; a
// different decision under the same operation key is rejected.
func (store *PostgresStore) RecordUncorrelated(
	ctx context.Context,
	spec UncorrelatedSpec,
) (StoredOutcome, error) {
	canonical, fingerprint, err := canonicalizeUncorrelated(spec)
	if err != nil {
		return StoredOutcome{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return StoredOutcome{}, fmt.Errorf("begin recording correlation outcome: %w", err)
	}
	defer tx.Rollback()

	var normalizedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT normalized_at
		FROM open_aspm.observation_normalizations
		WHERE workspace_id = $1 AND observation_id = $2
		  AND normalizer_name = $3 AND normalizer_version = $4`,
		spec.WorkspaceID, spec.ObservationID, spec.NormalizerName, spec.NormalizerVersion,
	).Scan(&normalizedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredOutcome{}, ErrNormalizationNotFound
	}
	if err != nil {
		return StoredOutcome{}, fmt.Errorf("read correlation source normalization: %w", err)
	}
	evaluatedAt := spec.EvaluatedAt.UTC().Round(0)
	if evaluatedAt.Before(normalizedAt.UTC().Round(0)) {
		return StoredOutcome{}, ErrInvalid
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.observation_correlation_outcomes (
			workspace_id, observation_id, normalizer_name, normalizer_version,
			algorithm, algorithm_version, state, reason_codes, evaluated_at,
			record_fingerprint
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (
			workspace_id, observation_id, algorithm, algorithm_version
		) DO NOTHING`,
		canonical.WorkspaceID, canonical.ObservationID, canonical.NormalizerName,
		canonical.NormalizerVersion, canonical.Algorithm, canonical.AlgorithmVersion,
		canonical.State, reasonStrings(canonical.Reasons), evaluatedAt, fingerprint[:],
	)
	if err != nil {
		return StoredOutcome{}, fmt.Errorf("insert correlation outcome: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return StoredOutcome{}, fmt.Errorf("read correlation outcome insert result: %w", err)
	}
	if rows == 0 {
		stored, existingFingerprint, err := selectStoredOutcome(ctx, tx, spec)
		if err != nil {
			return StoredOutcome{}, err
		}
		if !bytes.Equal(existingFingerprint, fingerprint[:]) {
			return StoredOutcome{}, ErrOutcomeConflict
		}
		if err := tx.Commit(); err != nil {
			return StoredOutcome{}, fmt.Errorf("finish correlation outcome replay: %w", err)
		}
		return stored, nil
	}
	if err := tx.Commit(); err != nil {
		return StoredOutcome{}, fmt.Errorf("commit correlation outcome: %w", err)
	}
	return StoredOutcome{
		WorkspaceID: spec.WorkspaceID, ObservationID: spec.ObservationID,
		Algorithm: spec.Algorithm, AlgorithmVersion: spec.AlgorithmVersion,
		State: StateUncorrelated, Reasons: cloneReasons(canonical.Reasons),
		EvaluatedAt: evaluatedAt, Created: true,
	}, nil
}

func selectStoredOutcome(
	ctx context.Context,
	tx *sql.Tx,
	spec UncorrelatedSpec,
) (StoredOutcome, []byte, error) {
	var stored StoredOutcome
	var state string
	var reasons []string
	var fingerprint []byte
	err := tx.QueryRowContext(ctx, `
		SELECT workspace_id, observation_id, algorithm, algorithm_version,
		       state, reason_codes, evaluated_at, record_fingerprint
		FROM open_aspm.observation_correlation_outcomes
		WHERE workspace_id = $1 AND observation_id = $2
		  AND algorithm = $3 AND algorithm_version = $4`,
		spec.WorkspaceID, spec.ObservationID, spec.Algorithm, spec.AlgorithmVersion,
	).Scan(
		&stored.WorkspaceID, &stored.ObservationID, &stored.Algorithm,
		&stored.AlgorithmVersion, &state, &reasons, &stored.EvaluatedAt, &fingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredOutcome{}, nil, ErrOutcomeConflict
	}
	if err != nil {
		return StoredOutcome{}, nil, fmt.Errorf("read existing correlation outcome: %w", err)
	}
	stored.State = OutcomeState(state)
	stored.Reasons = make([]ReasonCode, len(reasons))
	for index, reason := range reasons {
		stored.Reasons[index] = ReasonCode(reason)
	}
	return stored, fingerprint, nil
}

func reasonStrings(reasons []ReasonCode) []string {
	values := make([]string, len(reasons))
	for index, reason := range reasons {
		values[index] = string(reason)
	}
	return values
}
