package correlation

import (
	"regexp"
	"time"
)

const (
	DispatchAlgorithm        = "correlation-dispatch"
	DispatchAlgorithmVersion = "1"
)

var analysisKindPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

// DispatchSpec contains only the prerequisites needed to select a fingerprint
// family. Application identity is not a stable correlation target identity.
type DispatchSpec struct {
	WorkspaceID               string
	ObservationID             string
	NormalizerName            string
	NormalizerVersion         string
	StableTargetIdentityKnown bool
	AnalysisKind              string
	EvaluatedAt               time.Time
}

// NewDispatchUncorrelated records why correlation cannot yet select a
// fingerprint family. Family-specific inputs are deliberately not evaluated
// until a supported analysis kind is known.
func NewDispatchUncorrelated(spec DispatchSpec) (UncorrelatedSpec, error) {
	reasons := make([]ReasonCode, 0, 2)
	if !spec.StableTargetIdentityKnown {
		reasons = append(reasons, ReasonTargetIdentityUnknown)
	}
	if spec.AnalysisKind == "" || spec.AnalysisKind == "unknown" {
		reasons = append(reasons, ReasonAnalysisKindUnknown)
	} else if !analysisKindPattern.MatchString(spec.AnalysisKind) {
		return UncorrelatedSpec{}, ErrInvalid
	}
	if len(reasons) == 0 {
		return UncorrelatedSpec{}, ErrInvalid
	}
	outcome := UncorrelatedSpec{
		WorkspaceID: spec.WorkspaceID, ObservationID: spec.ObservationID,
		NormalizerName: spec.NormalizerName, NormalizerVersion: spec.NormalizerVersion,
		Algorithm: DispatchAlgorithm, AlgorithmVersion: DispatchAlgorithmVersion,
		Reasons: reasons, EvaluatedAt: spec.EvaluatedAt,
	}
	if _, _, err := canonicalizeUncorrelated(outcome); err != nil {
		return UncorrelatedSpec{}, err
	}
	return outcome, nil
}
