// Package authorization evaluates workspace and application capability grants.
package authorization

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrDenied  = errors.New("authorization denied")
	ErrInvalid = errors.New("invalid authorization input")
)

var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

// Request identifies one capability decision. TokenID is present for an API
// token and omitted only for an explicitly trusted internal reauthorization.
type Request struct {
	PrincipalID   string
	WorkspaceID   string
	Capability    string
	ApplicationID string
	TokenID       string
}

type decisionSpec struct {
	Request
	EvaluatedAt time.Time
}

func validateRequest(request Request) error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.WorkspaceID) ||
		!capabilityPattern.MatchString(request.Capability) ||
		(request.ApplicationID != "" && !validOpaqueID(request.ApplicationID)) ||
		(request.TokenID != "" && !validOpaqueID(request.TokenID)) {
		return ErrInvalid
	}
	return nil
}

func validOpaqueID(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 3 && length <= 128 &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}
