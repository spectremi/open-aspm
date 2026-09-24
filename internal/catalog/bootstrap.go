package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreateBootstrapApplication creates the initial opaque Application identity
// inside the operator bootstrap transaction. Catalog remains its write owner.
func CreateBootstrapApplication(
	ctx context.Context,
	tx *sql.Tx,
	workspaceID, applicationID string,
	createdAt time.Time,
) error {
	if tx == nil || !validOpaqueID(workspaceID) || !validOpaqueID(applicationID) || createdAt.IsZero() {
		return ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO open_aspm.applications (workspace_id, id, created_at)
		VALUES ($1, $2, $3)`, workspaceID, applicationID, createdAt); err != nil {
		return fmt.Errorf("insert bootstrap application: %w", err)
	}
	return nil
}
