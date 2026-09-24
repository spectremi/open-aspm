// Package correlation owns deterministic correlation decisions and their
// versioned, replay-safe outcomes.
package correlation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid               = errors.New("invalid correlation outcome input")
	ErrOutcomeConflict       = errors.New("correlation outcome conflicts with existing immutable result")
	ErrNormalizationNotFound = errors.New("correlation source normalization not found")
)

var algorithmNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

type OutcomeState string

const StateUncorrelated OutcomeState = "uncorrelated"

// ReasonCode explains which required correlation input was unavailable or
// unsafe. The order of these constants is the canonical persistence order.
type ReasonCode string

const (
	ReasonTargetIdentityUnknown        ReasonCode = "target_identity_unknown"
	ReasonAnalysisKindUnknown          ReasonCode = "analysis_kind_unknown"
	ReasonScannerFamilyUnknown         ReasonCode = "scanner_family_unknown"
	ReasonRuleIdentityUnknown          ReasonCode = "rule_identity_unknown"
	ReasonPackageIdentityUnknown       ReasonCode = "package_identity_unknown"
	ReasonVulnerabilityIdentityUnknown ReasonCode = "vulnerability_identity_unknown"
	ReasonLocationIdentityUnknown      ReasonCode = "location_identity_unknown"
	ReasonSourceContextUnknown         ReasonCode = "source_context_unknown"
	ReasonSourceContextUnsafe          ReasonCode = "source_context_unsafe"
)

var reasonOrder = map[ReasonCode]int{
	ReasonTargetIdentityUnknown:        0,
	ReasonAnalysisKindUnknown:          1,
	ReasonScannerFamilyUnknown:         2,
	ReasonRuleIdentityUnknown:          3,
	ReasonPackageIdentityUnknown:       4,
	ReasonVulnerabilityIdentityUnknown: 5,
	ReasonLocationIdentityUnknown:      6,
	ReasonSourceContextUnknown:         7,
	ReasonSourceContextUnsafe:          8,
}

// UncorrelatedSpec records that one algorithm version could not construct a
// reliable identity for an Observation. EvaluatedAt is audit time and is not
// part of the deterministic record fingerprint.
type UncorrelatedSpec struct {
	WorkspaceID       string
	ObservationID     string
	NormalizerName    string
	NormalizerVersion string
	Algorithm         string
	AlgorithmVersion  string
	Reasons           []ReasonCode
	EvaluatedAt       time.Time
}

type StoredOutcome struct {
	WorkspaceID      string
	ObservationID    string
	Algorithm        string
	AlgorithmVersion string
	State            OutcomeState
	Reasons          []ReasonCode
	EvaluatedAt      time.Time
	Created          bool
}

type canonicalOutcome struct {
	WorkspaceID       string       `json:"workspace_id"`
	ObservationID     string       `json:"observation_id"`
	NormalizerName    string       `json:"normalizer_name"`
	NormalizerVersion string       `json:"normalizer_version"`
	Algorithm         string       `json:"algorithm"`
	AlgorithmVersion  string       `json:"algorithm_version"`
	State             OutcomeState `json:"state"`
	Reasons           []ReasonCode `json:"reason_codes"`
}

func canonicalizeUncorrelated(
	spec UncorrelatedSpec,
) (canonicalOutcome, [sha256.Size]byte, error) {
	if !validOpaqueID(spec.WorkspaceID) || !validOpaqueID(spec.ObservationID) ||
		!algorithmNamePattern.MatchString(spec.NormalizerName) ||
		!validText(spec.NormalizerVersion, 1, 64) ||
		!algorithmNamePattern.MatchString(spec.Algorithm) ||
		!validText(spec.AlgorithmVersion, 1, 64) || spec.EvaluatedAt.IsZero() ||
		len(spec.Reasons) == 0 || len(spec.Reasons) > len(reasonOrder) {
		return canonicalOutcome{}, [sha256.Size]byte{}, ErrInvalid
	}
	reasons := append([]ReasonCode(nil), spec.Reasons...)
	for _, reason := range reasons {
		if _, ok := reasonOrder[reason]; !ok {
			return canonicalOutcome{}, [sha256.Size]byte{}, ErrInvalid
		}
	}
	sort.Slice(reasons, func(i, j int) bool {
		return reasonOrder[reasons[i]] < reasonOrder[reasons[j]]
	})
	for index, reason := range reasons {
		if index > 0 && reasons[index-1] == reason {
			return canonicalOutcome{}, [sha256.Size]byte{}, ErrInvalid
		}
	}
	canonical := canonicalOutcome{
		WorkspaceID: spec.WorkspaceID, ObservationID: spec.ObservationID,
		NormalizerName: spec.NormalizerName, NormalizerVersion: spec.NormalizerVersion,
		Algorithm: spec.Algorithm, AlgorithmVersion: spec.AlgorithmVersion,
		State: StateUncorrelated, Reasons: reasons,
	}
	encoded, _ := json.Marshal(canonical)
	return canonical, sha256.Sum256(encoded), nil
}

func validOpaqueID(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 3 && length <= 128 &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}

func validText(value string, minRunes, maxRunes int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minRunes && length <= maxRunes &&
		strings.IndexByte(value, 0) < 0
}

func cloneReasons(reasons []ReasonCode) []ReasonCode {
	return append([]ReasonCode(nil), reasons...)
}
