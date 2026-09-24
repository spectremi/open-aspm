package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

type store interface {
	Initialize(context.Context, installationSpec) error
	RotateToken(context.Context, rotationSpec) (Result, error)
}

type Service struct {
	store  store
	tokens tokenGenerator
	config Config
	now    func() time.Time
	random func([]byte) error
}

func NewService(store store, tokens tokenGenerator, config Config) (*Service, error) {
	if store == nil || tokens == nil || config.TokenTTL < minimumTokenTTL || config.TokenTTL > maximumTokenTTL {
		return nil, ErrInvalid
	}
	return &Service{
		store: store, tokens: tokens, config: config, now: time.Now,
		random: func(buffer []byte) error {
			_, err := rand.Read(buffer)
			return err
		},
	}, nil
}

func (service *Service) Initialize(ctx context.Context) (Result, error) {
	createdAt := service.timestamp()
	workspaceID, err := service.identifier("wsp_")
	if err != nil {
		return Result{}, err
	}
	applicationID, err := service.identifier("app_")
	if err != nil {
		return Result{}, err
	}
	principalID, err := service.identifier("prn_")
	if err != nil {
		return Result{}, err
	}
	roleID, err := service.identifier("role_")
	if err != nil {
		return Result{}, err
	}
	bindingID, err := service.identifier("bind_")
	if err != nil {
		return Result{}, err
	}
	tokenID, err := service.identifier("tok_")
	if err != nil {
		return Result{}, err
	}
	generated, err := service.tokens.Generate()
	if err != nil {
		return Result{}, fmt.Errorf("generate bootstrap token: %w", err)
	}
	result := Result{
		WorkspaceID: workspaceID, ApplicationID: applicationID, PrincipalID: principalID,
		TokenID: tokenID, Token: generated.Plaintext,
		TokenExpires: createdAt.Add(service.config.TokenTTL),
	}
	spec := installationSpec{
		Result: result, RoleID: roleID, BindingID: bindingID,
		TokenPrefix: generated.Prefix, Verifier: generated.Verifier, KeyID: generated.VerifierKeyID,
		CreatedAt: createdAt, Capabilities: append([]string(nil), initialCapabilities...),
	}
	if err := service.store.Initialize(ctx, spec); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (service *Service) RotateToken(ctx context.Context) (Result, error) {
	createdAt := service.timestamp()
	tokenID, err := service.identifier("tok_")
	if err != nil {
		return Result{}, err
	}
	generated, err := service.tokens.Generate()
	if err != nil {
		return Result{}, fmt.Errorf("generate replacement bootstrap token: %w", err)
	}
	return service.store.RotateToken(ctx, rotationSpec{
		TokenID: tokenID, Token: generated.Plaintext, TokenPrefix: generated.Prefix,
		Verifier: generated.Verifier, KeyID: generated.VerifierKeyID,
		CreatedAt: createdAt, TokenExpires: createdAt.Add(service.config.TokenTTL),
		Capabilities: append([]string(nil), initialCapabilities...),
	})
}

func (service *Service) identifier(prefix string) (string, error) {
	buffer := make([]byte, 20)
	if err := service.random(buffer); err != nil {
		return "", fmt.Errorf("generate bootstrap identifier: %w", err)
	}
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buffer)), nil
}

func (service *Service) timestamp() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}
