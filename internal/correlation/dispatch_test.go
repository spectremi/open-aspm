package correlation

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNewDispatchUncorrelatedPreservesOnlyDispatchReasons(t *testing.T) {
	evaluatedAt := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	base := DispatchSpec{
		WorkspaceID: "workspace-a", ObservationID: "observation-a",
		NormalizerName: "sarif", NormalizerVersion: "1", EvaluatedAt: evaluatedAt,
	}
	tests := []struct {
		name       string
		mutate     func(*DispatchSpec)
		wantReason []ReasonCode
	}{
		{
			name: "target and analysis unknown",
			wantReason: []ReasonCode{
				ReasonTargetIdentityUnknown, ReasonAnalysisKindUnknown,
			},
		},
		{
			name: "only analysis unknown",
			mutate: func(spec *DispatchSpec) {
				spec.StableTargetIdentityKnown = true
			},
			wantReason: []ReasonCode{ReasonAnalysisKindUnknown},
		},
		{
			name: "only target unknown",
			mutate: func(spec *DispatchSpec) {
				spec.AnalysisKind = "sast"
			},
			wantReason: []ReasonCode{ReasonTargetIdentityUnknown},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := base
			if test.mutate != nil {
				test.mutate(&spec)
			}
			outcome, err := NewDispatchUncorrelated(spec)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Algorithm != DispatchAlgorithm || outcome.AlgorithmVersion != DispatchAlgorithmVersion ||
				outcome.EvaluatedAt != evaluatedAt || !reflect.DeepEqual(outcome.Reasons, test.wantReason) {
				t.Fatalf("NewDispatchUncorrelated() = %+v", outcome)
			}
		})
	}
}

func TestNewDispatchUncorrelatedRejectsInvalidOrReadyInput(t *testing.T) {
	valid := DispatchSpec{
		WorkspaceID: "workspace-a", ObservationID: "observation-a",
		NormalizerName: "sarif", NormalizerVersion: "1",
		EvaluatedAt: time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC),
	}
	tests := map[string]func(*DispatchSpec){
		"ready for family selection": func(spec *DispatchSpec) {
			spec.StableTargetIdentityKnown = true
			spec.AnalysisKind = "sast"
		},
		"invalid analysis kind": func(spec *DispatchSpec) {
			spec.AnalysisKind = "SAST"
		},
		"invalid normalization": func(spec *DispatchSpec) {
			spec.NormalizerName = "SARIF"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if _, err := NewDispatchUncorrelated(spec); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewDispatchUncorrelated() error = %v, want ErrInvalid", err)
			}
		})
	}
}
