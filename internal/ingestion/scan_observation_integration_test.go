//go:build integration

package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/spectremi/open-aspm/internal/correlation"
	"github.com/spectremi/open-aspm/internal/finding"
)

func TestImmutableScanAndObservationPersistence(t *testing.T) {
	service, db := openReservationService(t)
	request := ReserveRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		IdempotencyKey: "scan-observation-source", ReportFormat: ReportFormat{Name: "sarif", Version: "2.1.0"},
	}
	reservation := reserveAndUpload(t, service, request, []byte(`{"version":"2.1.0","runs":[]}`))
	var artifactID string
	var receivedAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, committed_at FROM open_aspm.raw_artifacts
		WHERE workspace_id = $1 AND import_id = $2`,
		request.WorkspaceID, reservation.Import.ID,
	).Scan(&artifactID, &receivedAt); err != nil {
		t.Fatal(err)
	}
	recordedAt := receivedAt.Add(time.Second)
	scanStore, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	scanSpec := ScanSpec{
		ID: "scan-a", WorkspaceID: request.WorkspaceID, ImportID: reservation.Import.ID,
		ApplicationID: request.ApplicationID, RawArtifactID: artifactID, SourceRunIndex: 0,
		Result: ScanResultUnknown, Completeness: ScanCompletenessUnknown,
		ScannerName: "Example Scanner", ScannerVersion: "1.2.3",
		ParserName: "sarif", ParserVersion: "1", SourcePointer: "/runs/0", RecordedAt: recordedAt,
		Scope: ScanScope{
			SchemaVersion: 1, ScannerFamily: "unknown", AnalysisKind: "unknown",
			CoverageMetadata: json.RawMessage(`{"source":"sarif","coverage":"unknown"}`),
		},
	}
	storedScan, err := scanStore.RecordScan(context.Background(), scanSpec)
	if err != nil {
		t.Fatalf("RecordScan() error = %v", err)
	}
	if !storedScan.Created || storedScan.ID != scanSpec.ID {
		t.Fatalf("RecordScan() = %+v, want newly created scan", storedScan)
	}
	replaySpec := scanSpec
	replaySpec.ID = "scan-retry-candidate"
	replaySpec.RecordedAt = recordedAt.Add(time.Minute)
	replayedScan, err := scanStore.RecordScan(context.Background(), replaySpec)
	if err != nil {
		t.Fatalf("RecordScan() replay error = %v", err)
	}
	if replayedScan.Created || replayedScan.ID != scanSpec.ID || !replayedScan.RecordedAt.Equal(recordedAt) {
		t.Fatalf("RecordScan() replay = %+v, want original immutable scan", replayedScan)
	}
	conflictingScan := replaySpec
	conflictingScan.ScannerVersion = "9.9.9"
	if _, err := scanStore.RecordScan(context.Background(), conflictingScan); !errors.Is(err, ErrScanConflict) {
		t.Fatalf("conflicting RecordScan() error = %v, want ErrScanConflict", err)
	}

	observationStore, err := finding.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ruleIndex := 3
	artifactIndex := 0
	line := 42
	observationSpec := finding.ObservationSpec{
		ID: "observation-a", WorkspaceID: request.WorkspaceID, ScanID: scanSpec.ID,
		RawArtifactID: artifactID, SourceResultIndex: 0, ParserName: "sarif", ParserVersion: "1",
		SourcePointer: "/runs/0/results/0", SourceRuleID: "SQL-001", SourceRuleIndex: &ruleIndex,
		SourceSeverity: "error", MessageText: "Synthetic SQL finding", MessageArguments: []string{"example"},
		Locations: []finding.Location{{
			Ordinal: 0, SourcePointer: "/runs/0/results/0/locations/0",
			URI: "src/example.go", ArtifactIndex: &artifactIndex, StartLine: &line,
		}},
		Fingerprints: []finding.SourceFingerprint{
			{Kind: finding.FingerprintPartial, Name: "primaryLocationLineHash", Value: "synthetic-partial"},
			{Kind: finding.FingerprintComplete, Name: "example/v1", Value: "synthetic-complete"},
		},
		RecordedAt: recordedAt,
	}
	storedObservation, err := observationStore.RecordObservation(context.Background(), observationSpec)
	if err != nil {
		t.Fatalf("RecordObservation() error = %v", err)
	}
	if !storedObservation.Created || storedObservation.ID != observationSpec.ID {
		t.Fatalf("RecordObservation() = %+v, want newly created observation", storedObservation)
	}
	replayedObservationSpec := observationSpec
	replayedObservationSpec.ID = "observation-retry-candidate"
	replayedObservationSpec.RecordedAt = recordedAt.Add(time.Minute)
	// Ordering is presentation-only; explicit ordinal and kind/name make the
	// immutable content fingerprint deterministic.
	replayedObservationSpec.Fingerprints = []finding.SourceFingerprint{
		observationSpec.Fingerprints[1], observationSpec.Fingerprints[0],
	}
	replayedObservation, err := observationStore.RecordObservation(context.Background(), replayedObservationSpec)
	if err != nil {
		t.Fatalf("RecordObservation() replay error = %v", err)
	}
	if replayedObservation.Created || replayedObservation.ID != observationSpec.ID ||
		!replayedObservation.RecordedAt.Equal(recordedAt) {
		t.Fatalf("RecordObservation() replay = %+v, want original immutable observation", replayedObservation)
	}
	conflictingObservation := replayedObservationSpec
	conflictingObservation.MessageText = "different source statement"
	if _, err := observationStore.RecordObservation(context.Background(), conflictingObservation); !errors.Is(err, finding.ErrObservationConflict) {
		t.Fatalf("conflicting RecordObservation() error = %v, want ErrObservationConflict", err)
	}

	normalizationSpec := finding.NormalizationSpec{
		WorkspaceID: request.WorkspaceID, ObservationID: storedObservation.ID,
		NormalizerName: "sarif", NormalizerVersion: "1",
		Category: finding.CategoryUnknown, Severity: finding.SeverityHigh,
		RuleKind: finding.RuleSource, RuleID: observationSpec.SourceRuleID,
		Location: finding.NormalizedLocation{
			Kind: finding.LocationArtifact, URI: "src/example.go", StartLine: &line,
		},
		NormalizedAt: recordedAt.Add(time.Second),
	}
	storedNormalization, err := observationStore.RecordNormalization(context.Background(), normalizationSpec)
	if err != nil {
		t.Fatalf("RecordNormalization() error = %v", err)
	}
	if !storedNormalization.Created || storedNormalization.ObservationID != storedObservation.ID {
		t.Fatalf("RecordNormalization() = %+v, want newly created normalization", storedNormalization)
	}
	replayedNormalizationSpec := normalizationSpec
	replayedNormalizationSpec.NormalizedAt = normalizationSpec.NormalizedAt.Add(time.Minute)
	replayedNormalization, err := observationStore.RecordNormalization(context.Background(), replayedNormalizationSpec)
	if err != nil {
		t.Fatalf("RecordNormalization() replay error = %v", err)
	}
	if replayedNormalization.Created || !replayedNormalization.NormalizedAt.Equal(normalizationSpec.NormalizedAt) {
		t.Fatalf("RecordNormalization() replay = %+v, want retained immutable normalization", replayedNormalization)
	}
	conflictingNormalization := replayedNormalizationSpec
	conflictingNormalization.Severity = finding.SeverityMedium
	if _, err := observationStore.RecordNormalization(context.Background(), conflictingNormalization); !errors.Is(err, finding.ErrNormalizationConflict) {
		t.Fatalf("conflicting RecordNormalization() error = %v, want ErrNormalizationConflict", err)
	}
	newVersionNormalization := conflictingNormalization
	newVersionNormalization.NormalizerVersion = "2"
	newVersion, err := observationStore.RecordNormalization(context.Background(), newVersionNormalization)
	if err != nil || !newVersion.Created {
		t.Fatalf("new-version RecordNormalization() = %+v, %v; want independent version", newVersion, err)
	}

	correlationStore, err := correlation.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	outcomeSpec := correlation.UncorrelatedSpec{
		WorkspaceID: request.WorkspaceID, ObservationID: storedObservation.ID,
		NormalizerName: "sarif", NormalizerVersion: "1",
		Algorithm: "sast", AlgorithmVersion: "1",
		Reasons: []correlation.ReasonCode{
			correlation.ReasonScannerFamilyUnknown, correlation.ReasonTargetIdentityUnknown,
			correlation.ReasonAnalysisKindUnknown, correlation.ReasonSourceContextUnknown,
		},
		EvaluatedAt: normalizationSpec.NormalizedAt.Add(time.Second),
	}
	storedOutcome, err := correlationStore.RecordUncorrelated(context.Background(), outcomeSpec)
	if err != nil {
		t.Fatalf("RecordUncorrelated() error = %v", err)
	}
	wantReasons := []correlation.ReasonCode{
		correlation.ReasonTargetIdentityUnknown, correlation.ReasonAnalysisKindUnknown,
		correlation.ReasonScannerFamilyUnknown, correlation.ReasonSourceContextUnknown,
	}
	if !storedOutcome.Created || storedOutcome.State != correlation.StateUncorrelated ||
		!slices.Equal(storedOutcome.Reasons, wantReasons) {
		t.Fatalf("RecordUncorrelated() = %+v, want canonical new outcome", storedOutcome)
	}
	replayedOutcomeSpec := outcomeSpec
	replayedOutcomeSpec.EvaluatedAt = outcomeSpec.EvaluatedAt.Add(time.Minute)
	replayedOutcomeSpec.Reasons = []correlation.ReasonCode{
		correlation.ReasonSourceContextUnknown, correlation.ReasonAnalysisKindUnknown,
		correlation.ReasonTargetIdentityUnknown, correlation.ReasonScannerFamilyUnknown,
	}
	replayedOutcome, err := correlationStore.RecordUncorrelated(context.Background(), replayedOutcomeSpec)
	if err != nil {
		t.Fatalf("RecordUncorrelated() replay error = %v", err)
	}
	if replayedOutcome.Created || !replayedOutcome.EvaluatedAt.Equal(outcomeSpec.EvaluatedAt) ||
		!slices.Equal(replayedOutcome.Reasons, wantReasons) {
		t.Fatalf("RecordUncorrelated() replay = %+v, want retained immutable outcome", replayedOutcome)
	}
	conflictingOutcome := replayedOutcomeSpec
	conflictingOutcome.Reasons = []correlation.ReasonCode{correlation.ReasonTargetIdentityUnknown}
	if _, err := correlationStore.RecordUncorrelated(context.Background(), conflictingOutcome); !errors.Is(err, correlation.ErrOutcomeConflict) {
		t.Fatalf("conflicting RecordUncorrelated() error = %v, want ErrOutcomeConflict", err)
	}
	newOutcomeVersion := conflictingOutcome
	newOutcomeVersion.AlgorithmVersion = "2"
	newOutcome, err := correlationStore.RecordUncorrelated(context.Background(), newOutcomeVersion)
	if err != nil || !newOutcome.Created {
		t.Fatalf("new-version RecordUncorrelated() = %+v, %v; want independent version", newOutcome, err)
	}

	var observations, locations, fingerprints, normalizations, outcomes int
	if err := db.QueryRow(`SELECT count(*) FROM open_aspm.observations WHERE workspace_id = $1`, request.WorkspaceID).
		Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM open_aspm.observation_locations WHERE workspace_id = $1`, request.WorkspaceID).
		Scan(&locations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM open_aspm.observation_fingerprints WHERE workspace_id = $1`, request.WorkspaceID).
		Scan(&fingerprints); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM open_aspm.observation_normalizations WHERE workspace_id = $1`, request.WorkspaceID).
		Scan(&normalizations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM open_aspm.observation_correlation_outcomes WHERE workspace_id = $1`, request.WorkspaceID).
		Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if observations != 1 || locations != 1 || fingerprints != 2 || normalizations != 2 || outcomes != 2 {
		t.Fatalf("stored rows = observations %d, locations %d, fingerprints %d, normalizations %d, outcomes %d; want 1, 1, 2, 2, 2",
			observations, locations, fingerprints, normalizations, outcomes)
	}
	if _, err := db.Exec(`UPDATE open_aspm.observations SET message_text = 'changed' WHERE workspace_id = $1`, request.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable observations")
	}
	if _, err := db.Exec(`UPDATE open_aspm.scans SET result = 'succeeded' WHERE workspace_id = $1`, request.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable scans")
	}
	if _, err := db.Exec(`UPDATE open_aspm.observation_normalizations SET severity = 'critical' WHERE workspace_id = $1`, request.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable normalizations")
	}
	if _, err := db.Exec(`UPDATE open_aspm.observation_correlation_outcomes SET state = 'correlated' WHERE workspace_id = $1`, request.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable correlation outcomes")
	}
}

func TestConcurrentReplayAndWorkspaceIsolation(t *testing.T) {
	service, db := openReservationService(t)
	request := ReserveRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		IdempotencyKey: "concurrent-scan-source", ReportFormat: ReportFormat{Name: "sarif", Version: "2.1.0"},
	}
	reservation := reserveAndUpload(t, service, request, []byte(`{"version":"2.1.0","runs":[{}]}`))
	var artifactID string
	var receivedAt time.Time
	if err := db.QueryRow(`
		SELECT id, committed_at FROM open_aspm.raw_artifacts
		WHERE workspace_id = $1 AND import_id = $2`, request.WorkspaceID, reservation.Import.ID,
	).Scan(&artifactID, &receivedAt); err != nil {
		t.Fatal(err)
	}
	scanStore, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	baseScan := ScanSpec{
		WorkspaceID: request.WorkspaceID, ImportID: reservation.Import.ID,
		ApplicationID: request.ApplicationID, RawArtifactID: artifactID, SourceRunIndex: 0,
		Result: ScanResultUnknown, Completeness: ScanCompletenessUnknown, ScannerName: "Concurrent Scanner",
		ParserName: "sarif", ParserVersion: "1", SourcePointer: "/runs/0", RecordedAt: receivedAt.Add(time.Second),
		Scope: ScanScope{SchemaVersion: 1, ScannerFamily: "unknown", AnalysisKind: "unknown"},
	}
	const workers = 8
	var wait sync.WaitGroup
	results := make(chan StoredScan, workers)
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			spec := baseScan
			spec.ID = fmt.Sprintf("scan-concurrent-%d", index)
			stored, err := scanStore.RecordScan(context.Background(), spec)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- stored
		}(index)
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent RecordScan() error = %v", err)
	}
	var authoritativeScanID string
	created := 0
	for result := range results {
		if authoritativeScanID == "" {
			authoritativeScanID = result.ID
		}
		if result.ID != authoritativeScanID {
			t.Fatalf("concurrent scan IDs include %q and %q", authoritativeScanID, result.ID)
		}
		if result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent scan creations = %d, want 1", created)
	}

	observationStore, err := finding.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	baseObservation := finding.ObservationSpec{
		WorkspaceID: request.WorkspaceID, ScanID: authoritativeScanID, RawArtifactID: artifactID,
		SourceResultIndex: 0, ParserName: "sarif", ParserVersion: "1",
		SourcePointer: "/runs/0/results/0", MessageText: "Concurrent statement",
		RecordedAt: receivedAt.Add(time.Second),
	}
	observationResults := make(chan finding.StoredObservation, workers)
	observationErrors := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			spec := baseObservation
			spec.ID = fmt.Sprintf("observation-concurrent-%d", index)
			stored, err := observationStore.RecordObservation(context.Background(), spec)
			if err != nil {
				observationErrors <- err
				return
			}
			observationResults <- stored
		}(index)
	}
	wait.Wait()
	close(observationResults)
	close(observationErrors)
	for err := range observationErrors {
		t.Errorf("concurrent RecordObservation() error = %v", err)
	}
	var authoritativeObservationID string
	created = 0
	for result := range observationResults {
		if authoritativeObservationID == "" {
			authoritativeObservationID = result.ID
		}
		if result.ID != authoritativeObservationID {
			t.Fatalf("concurrent observation IDs include %q and %q", authoritativeObservationID, result.ID)
		}
		if result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent observation creations = %d, want 1", created)
	}
	normalizationResults := make(chan finding.StoredNormalization, workers)
	normalizationErrors := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			stored, err := observationStore.RecordNormalization(context.Background(), finding.NormalizationSpec{
				WorkspaceID: request.WorkspaceID, ObservationID: authoritativeObservationID,
				NormalizerName: "sarif", NormalizerVersion: "1",
				Category: finding.CategoryUnknown, Severity: finding.SeverityUnknown,
				RuleKind:     finding.RuleUnknown,
				Location:     finding.NormalizedLocation{Kind: finding.LocationUnknown},
				NormalizedAt: receivedAt.Add(2 * time.Second),
			})
			if err != nil {
				normalizationErrors <- err
				return
			}
			normalizationResults <- stored
		}()
	}
	wait.Wait()
	close(normalizationResults)
	close(normalizationErrors)
	for err := range normalizationErrors {
		t.Errorf("concurrent RecordNormalization() error = %v", err)
	}
	created = 0
	for result := range normalizationResults {
		if result.ObservationID != authoritativeObservationID {
			t.Fatalf("concurrent normalization observation ID = %q", result.ObservationID)
		}
		if result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent normalization creations = %d, want 1", created)
	}
	correlationStore, err := correlation.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	outcomeResults := make(chan correlation.StoredOutcome, workers)
	outcomeErrors := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			reasons := []correlation.ReasonCode{
				correlation.ReasonSourceContextUnknown, correlation.ReasonTargetIdentityUnknown,
				correlation.ReasonAnalysisKindUnknown,
			}
			if index%2 == 0 {
				slices.Reverse(reasons)
			}
			stored, err := correlationStore.RecordUncorrelated(context.Background(), correlation.UncorrelatedSpec{
				WorkspaceID: request.WorkspaceID, ObservationID: authoritativeObservationID,
				NormalizerName: "sarif", NormalizerVersion: "1",
				Algorithm: "sast", AlgorithmVersion: "1", Reasons: reasons,
				EvaluatedAt: receivedAt.Add(3 * time.Second),
			})
			if err != nil {
				outcomeErrors <- err
				return
			}
			outcomeResults <- stored
		}(index)
	}
	wait.Wait()
	close(outcomeResults)
	close(outcomeErrors)
	for err := range outcomeErrors {
		t.Errorf("concurrent RecordUncorrelated() error = %v", err)
	}
	created = 0
	for result := range outcomeResults {
		if result.ObservationID != authoritativeObservationID {
			t.Fatalf("concurrent outcome observation ID = %q", result.ObservationID)
		}
		if result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent correlation outcome creations = %d, want 1", created)
	}
	crossWorkspace := baseObservation
	crossWorkspace.ID = "observation-cross-workspace"
	crossWorkspace.WorkspaceID = "workspace-b"
	if _, err := observationStore.RecordObservation(context.Background(), crossWorkspace); !errors.Is(err, finding.ErrScanNotFound) {
		t.Fatalf("cross-workspace RecordObservation() error = %v, want ErrScanNotFound", err)
	}
	if _, err := observationStore.RecordNormalization(context.Background(), finding.NormalizationSpec{
		WorkspaceID: "workspace-b", ObservationID: authoritativeObservationID,
		NormalizerName: "sarif", NormalizerVersion: "1",
		Category: finding.CategoryUnknown, Severity: finding.SeverityUnknown,
		RuleKind:     finding.RuleUnknown,
		Location:     finding.NormalizedLocation{Kind: finding.LocationUnknown},
		NormalizedAt: receivedAt.Add(2 * time.Second),
	}); !errors.Is(err, finding.ErrObservationNotFound) {
		t.Fatalf("cross-workspace RecordNormalization() error = %v, want ErrObservationNotFound", err)
	}
	if _, err := correlationStore.RecordUncorrelated(context.Background(), correlation.UncorrelatedSpec{
		WorkspaceID: "workspace-b", ObservationID: authoritativeObservationID,
		NormalizerName: "sarif", NormalizerVersion: "1",
		Algorithm: "sast", AlgorithmVersion: "1",
		Reasons:     []correlation.ReasonCode{correlation.ReasonTargetIdentityUnknown},
		EvaluatedAt: receivedAt.Add(3 * time.Second),
	}); !errors.Is(err, correlation.ErrNormalizationNotFound) {
		t.Fatalf("cross-workspace RecordUncorrelated() error = %v, want ErrNormalizationNotFound", err)
	}
}
