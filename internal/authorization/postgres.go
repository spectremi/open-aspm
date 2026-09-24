package authorization

import (
	"context"
	"database/sql"
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

func (store *PostgresStore) IsAllowed(ctx context.Context, spec decisionSpec) (bool, error) {
	if err := validateRequest(spec.Request); err != nil || spec.EvaluatedAt.IsZero() {
		return false, ErrInvalid
	}
	requireToken := spec.TokenID != ""
	var allowed bool
	err := store.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM open_aspm.principals AS principal
			JOIN open_aspm.workspace_memberships AS membership
			  ON membership.principal_id = principal.id
			 AND membership.workspace_id = $2
			WHERE principal.id = $1
			  AND principal.state = 'active'
			  AND membership.state = 'active'
			  AND membership.valid_from <= $6
			  AND (membership.valid_until IS NULL OR membership.valid_until > $6)
			  AND (
				$4 = ''
				OR EXISTS (
					SELECT 1
					FROM open_aspm.applications AS application
					WHERE application.workspace_id = membership.workspace_id
					  AND application.id = $4
				)
			  )
			  AND (
				principal.kind <> 'service_account'
				OR EXISTS (
					SELECT 1
					FROM open_aspm.service_accounts AS service_account
					WHERE service_account.workspace_id = membership.workspace_id
					  AND service_account.principal_id = principal.id
					  AND (
						service_account.expires_at IS NULL
						OR service_account.expires_at > $6
					  )
				)
			  )
			  AND EXISTS (
				SELECT 1
				FROM open_aspm.role_bindings AS binding
				JOIN open_aspm.role_capabilities AS role_capability
				  ON role_capability.workspace_id = binding.workspace_id
				 AND role_capability.role_id = binding.role_id
				WHERE binding.workspace_id = membership.workspace_id
				  AND binding.principal_id = principal.id
				  AND role_capability.capability = $3
				  AND binding.valid_from <= $6
				  AND (binding.valid_until IS NULL OR binding.valid_until > $6)
				  AND (
					($4 = '' AND binding.scope_type = 'workspace')
					OR (
						$4 <> '' AND (
							binding.scope_type = 'workspace'
							OR (
								binding.scope_type = 'application'
								AND binding.application_id = $4
							)
						)
					)
				  )
			  )
			  AND (
				NOT $7
				OR EXISTS (
					SELECT 1
					FROM open_aspm.api_tokens AS token
					JOIN open_aspm.api_token_capabilities AS token_capability
					  ON token_capability.workspace_id = token.workspace_id
					 AND token_capability.token_id = token.id
					WHERE token.workspace_id = membership.workspace_id
					  AND token.principal_id = principal.id
					  AND token.id = $5
					  AND token_capability.capability = $3
					  AND token.created_at <= $6
					  AND token.expires_at > $6
					  AND token.revoked_at IS NULL
					  AND (
						token.application_scope_mode = 'workspace'
						OR (
							token.application_scope_mode = 'explicit'
							AND $4 <> ''
							AND EXISTS (
								SELECT 1
								FROM open_aspm.api_token_application_scopes AS token_scope
								WHERE token_scope.workspace_id = token.workspace_id
								  AND token_scope.token_id = token.id
								  AND token_scope.application_id = $4
							)
						)
					  )
				)
			  )
		)`,
		spec.PrincipalID, spec.WorkspaceID, spec.Capability, spec.ApplicationID,
		spec.TokenID, spec.EvaluatedAt, requireToken,
	).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("query authorization decision: %w", err)
	}
	return allowed, nil
}
