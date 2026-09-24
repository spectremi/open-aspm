package authorization

import (
	"context"
	"fmt"
	"time"
)

type decisionStore interface {
	IsAllowed(context.Context, decisionSpec) (bool, error)
}

// Service applies fail-closed capability authorization through the durable
// identity, membership, role, and optional API-token scopes.
type Service struct {
	store decisionStore
	now   func() time.Time
}

func NewService(store decisionStore) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, now: time.Now}, nil
}

func (service *Service) Authorize(ctx context.Context, request Request) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	allowed, err := service.store.IsAllowed(ctx, decisionSpec{
		Request: request, EvaluatedAt: service.now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		return fmt.Errorf("evaluate authorization: %w", err)
	}
	if !allowed {
		return ErrDenied
	}
	return nil
}
