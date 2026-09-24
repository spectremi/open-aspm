package correlation

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCanonicalizeUncorrelatedIsDeterministic(t *testing.T) {
	base := UncorrelatedSpec{
		WorkspaceID: "workspace-a", ObservationID: "observation-a",
		NormalizerName: "sarif", NormalizerVersion: "1",
		Algorithm: "sast", AlgorithmVersion: "1",
		Reasons: []ReasonCode{
			ReasonSourceContextUnknown, ReasonTargetIdentityUnknown, ReasonScannerFamilyUnknown,
		},
		EvaluatedAt: time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC),
	}
	canonicalA, fingerprintA, err := canonicalizeUncorrelated(base)
	if err != nil {
		t.Fatal(err)
	}
	retry := base
	retry.EvaluatedAt = base.EvaluatedAt.Add(time.Hour)
	retry.Reasons = []ReasonCode{
		ReasonScannerFamilyUnknown, ReasonSourceContextUnknown, ReasonTargetIdentityUnknown,
	}
	canonicalB, fingerprintB, err := canonicalizeUncorrelated(retry)
	if err != nil {
		t.Fatal(err)
	}
	wantReasons := []ReasonCode{
		ReasonTargetIdentityUnknown, ReasonScannerFamilyUnknown, ReasonSourceContextUnknown,
	}
	if fingerprintA != fingerprintB || !reflect.DeepEqual(canonicalA, canonicalB) ||
		!reflect.DeepEqual(canonicalA.Reasons, wantReasons) {
		t.Fatalf("canonical replay differs: %+v/%x != %+v/%x", canonicalA, fingerprintA, canonicalB, fingerprintB)
	}
	if !reflect.DeepEqual(base.Reasons, []ReasonCode{
		ReasonSourceContextUnknown, ReasonTargetIdentityUnknown, ReasonScannerFamilyUnknown,
	}) {
		t.Fatalf("canonicalization mutated caller reasons: %+v", base.Reasons)
	}

	changed := retry
	changed.Reasons = []ReasonCode{ReasonTargetIdentityUnknown}
	_, fingerprintChanged, err := canonicalizeUncorrelated(changed)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprintChanged == fingerprintA {
		t.Fatal("different reasons produced the same record fingerprint")
	}
}

func TestCanonicalizeUncorrelatedRejectsInvalidInput(t *testing.T) {
	valid := UncorrelatedSpec{
		WorkspaceID: "workspace-a", ObservationID: "observation-a",
		NormalizerName: "sarif", NormalizerVersion: "1",
		Algorithm: "sast", AlgorithmVersion: "1",
		Reasons:     []ReasonCode{ReasonTargetIdentityUnknown},
		EvaluatedAt: time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC),
	}
	tests := map[string]func(*UncorrelatedSpec){
		"workspace":   func(spec *UncorrelatedSpec) { spec.WorkspaceID = " bad" },
		"observation": func(spec *UncorrelatedSpec) { spec.ObservationID = "x" },
		"normalizer":  func(spec *UncorrelatedSpec) { spec.NormalizerName = "SARIF" },
		"normalizer version": func(spec *UncorrelatedSpec) {
			spec.NormalizerVersion = ""
		},
		"algorithm": func(spec *UncorrelatedSpec) { spec.Algorithm = "SAST" },
		"algorithm version": func(spec *UncorrelatedSpec) {
			spec.AlgorithmVersion = ""
		},
		"time":      func(spec *UncorrelatedSpec) { spec.EvaluatedAt = time.Time{} },
		"no reason": func(spec *UncorrelatedSpec) { spec.Reasons = nil },
		"unknown reason": func(spec *UncorrelatedSpec) {
			spec.Reasons = []ReasonCode{"invented"}
		},
		"duplicate reason": func(spec *UncorrelatedSpec) {
			spec.Reasons = []ReasonCode{ReasonTargetIdentityUnknown, ReasonTargetIdentityUnknown}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := valid
			spec.Reasons = cloneReasons(valid.Reasons)
			mutate(&spec)
			if _, _, err := canonicalizeUncorrelated(spec); !errors.Is(err, ErrInvalid) {
				t.Fatalf("canonicalizeUncorrelated() error = %v, want ErrInvalid", err)
			}
		})
	}
}
