package correlation

import (
	"regexp"
	"time"
)

const (
	DispatchAlgorithm              = "correlation-dispatch"
	DispatchAlgorithmVersion       = "1"
	DispatchMappedAlgorithmVersion = "2"
)

var analysisKindPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

// DispatchSpec contains the prerequisites needed to select a fingerprint
// family and the first SAST-family blockers. Application identity is not a
// stable correlation target identity.
type DispatchSpec struct {
	WorkspaceID               string
	ObservationID             string
	NormalizerName            string
	NormalizerVersion         string
	StableTargetIdentityKnown bool
	AnalysisKind              string
	ScannerFamily             string
	SourceContextKnown        bool
	SourceContextSafe         bool
	EvaluatedAt               time.Time
}

// NewDispatchUncorrelated records why correlation cannot yet select or run a
// fingerprint family. Family-specific inputs are deliberately not evaluated
// until a supported target and analysis kind are known.
func NewDispatchUncorrelated(spec DispatchSpec) (UncorrelatedSpec, error) {
	reasons := make([]ReasonCode, 0, 2)
	algorithmVersion := DispatchAlgorithmVersion
	if !spec.StableTargetIdentityKnown {
		reasons = append(reasons, ReasonTargetIdentityUnknown)
	}
	if spec.AnalysisKind == "" || spec.AnalysisKind == "unknown" {
		reasons = append(reasons, ReasonAnalysisKindUnknown)
	} else if !analysisKindPattern.MatchString(spec.AnalysisKind) {
		return UncorrelatedSpec{}, ErrInvalid
	}
	if spec.SourceContextSafe && !spec.SourceContextKnown {
		return UncorrelatedSpec{}, ErrInvalid
	}
	if len(reasons) == 0 {
		algorithmVersion = DispatchMappedAlgorithmVersion
		if spec.AnalysisKind != "sast" {
			return UncorrelatedSpec{}, ErrInvalid
		}
		if spec.ScannerFamily == "" || spec.ScannerFamily == "unknown" {
			reasons = append(reasons, ReasonScannerFamilyUnknown)
		} else if !analysisKindPattern.MatchString(spec.ScannerFamily) {
			return UncorrelatedSpec{}, ErrInvalid
		}
		if !spec.SourceContextKnown {
			reasons = append(reasons, ReasonSourceContextUnknown)
		} else if !spec.SourceContextSafe {
			reasons = append(reasons, ReasonSourceContextUnsafe)
		}
	}
	if len(reasons) == 0 {
		return UncorrelatedSpec{}, ErrInvalid
	}
	outcome := UncorrelatedSpec{
		WorkspaceID: spec.WorkspaceID, ObservationID: spec.ObservationID,
		NormalizerName: spec.NormalizerName, NormalizerVersion: spec.NormalizerVersion,
		Algorithm: DispatchAlgorithm, AlgorithmVersion: algorithmVersion,
		Reasons: reasons, EvaluatedAt: spec.EvaluatedAt,
	}
	if _, _, err := canonicalizeUncorrelated(outcome); err != nil {
		return UncorrelatedSpec{}, err
	}
	return outcome, nil
}
