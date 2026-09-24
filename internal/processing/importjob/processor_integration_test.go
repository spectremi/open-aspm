//go:build integration

package importjob

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spectremi/open-aspm/internal/blobstore/filesystem"
	"github.com/spectremi/open-aspm/internal/catalog"
	"github.com/spectremi/open-aspm/internal/correlation"
	"github.com/spectremi/open-aspm/internal/database"
	"github.com/spectremi/open-aspm/internal/finding"
	"github.com/spectremi/open-aspm/internal/ingestion"
	"github.com/spectremi/open-aspm/internal/jobqueue"
	sarifnormalization "github.com/spectremi/open-aspm/internal/normalization/sarif"
	"github.com/spectremi/open-aspm/internal/parsing/sarif"
)

func TestImportProcessorPersistsAndReplaysSARIF(t *testing.T) {
	harness := openProcessorHarness(t)
	report, err := os.ReadFile("../../../testdata/sarif/valid/representative.sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	job := harness.createImportJob(t, "successful", report)
	outcome := harness.processor.Handle(context.Background(), job)
	if outcome.Kind != jobqueue.OutcomeSucceeded {
		t.Fatalf("Handle() = %+v, want success", outcome)
	}
	// Delivery replay observes the public terminal result and produces no new
	// authoritative records.
	replay := harness.processor.Handle(context.Background(), job)
	if replay.Kind != jobqueue.OutcomeSucceeded {
		t.Fatalf("Handle() replay = %+v, want success", replay)
	}

	var importState, operationState string
	var resultJSON []byte
	if err := harness.db.QueryRow(`
		SELECT imp.state, op.state, op.result
		FROM open_aspm.imports AS imp
		JOIN open_aspm.operations AS op
		  ON op.workspace_id = imp.workspace_id AND op.import_id = imp.id
		WHERE imp.workspace_id = $1 AND imp.id = $2`, job.WorkspaceID, importIDFromJob(t, job),
	).Scan(&importState, &operationState, &resultJSON); err != nil {
		t.Fatal(err)
	}
	if importState != "succeeded" || operationState != "succeeded" {
		t.Fatalf("terminal states = import %q operation %q", importState, operationState)
	}
	var result struct {
		ScansCreated int `json:"scans_created"`
	}
	if err := json.Unmarshal(resultJSON, &result); err != nil || result.ScansCreated != 2 {
		t.Fatalf("operation result = %s, error %v", resultJSON, err)
	}

	counts := map[string]int{}
	for name, query := range map[string]string{
		"parse_outputs":        `SELECT count(*) FROM open_aspm.import_parse_outputs WHERE workspace_id = $1 AND import_id = $2`,
		"warnings":             `SELECT count(*) FROM open_aspm.import_parse_warnings WHERE workspace_id = $1 AND import_id = $2`,
		"scans":                `SELECT count(*) FROM open_aspm.scans WHERE workspace_id = $1 AND import_id = $2`,
		"observations":         `SELECT count(*) FROM open_aspm.observations AS observation JOIN open_aspm.scans AS scan ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
		"normalizations":       `SELECT count(*) FROM open_aspm.observation_normalizations AS normalization JOIN open_aspm.observations AS observation ON observation.workspace_id = normalization.workspace_id AND observation.id = normalization.observation_id JOIN open_aspm.scans AS scan ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
		"correlation_outcomes": `SELECT count(*) FROM open_aspm.observation_correlation_outcomes AS outcome JOIN open_aspm.observations AS observation ON observation.workspace_id = outcome.workspace_id AND observation.id = outcome.observation_id JOIN open_aspm.scans AS scan ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
		"locations":            `SELECT count(*) FROM open_aspm.observation_locations AS location JOIN open_aspm.observations AS observation ON observation.workspace_id = location.workspace_id AND observation.id = location.observation_id JOIN open_aspm.scans AS scan ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
		"fingerprints":         `SELECT count(*) FROM open_aspm.observation_fingerprints AS fingerprint JOIN open_aspm.observations AS observation ON observation.workspace_id = fingerprint.workspace_id AND observation.id = fingerprint.observation_id JOIN open_aspm.scans AS scan ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
	} {
		var count int
		if err := harness.db.QueryRow(query, job.WorkspaceID, importIDFromJob(t, job)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts[name] = count
	}
	if counts["parse_outputs"] != 1 || counts["warnings"] == 0 || counts["scans"] != 2 ||
		counts["observations"] != 3 || counts["normalizations"] != 3 ||
		counts["correlation_outcomes"] != 3 || counts["locations"] != 2 || counts["fingerprints"] != 3 {
		t.Fatalf("persisted counts = %+v", counts)
	}
	var dispatchOutcomes int
	if err := harness.db.QueryRow(`
		SELECT count(*) FROM open_aspm.observation_correlation_outcomes AS outcome
		JOIN open_aspm.observations AS observation
		  ON observation.workspace_id = outcome.workspace_id
		 AND observation.id = outcome.observation_id
		JOIN open_aspm.scans AS scan
		  ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2
		  AND outcome.algorithm = 'correlation-dispatch'
		  AND outcome.algorithm_version = '1'
		  AND outcome.state = 'uncorrelated'
		  AND outcome.reason_codes = ARRAY[
		    'target_identity_unknown', 'analysis_kind_unknown'
		  ]::varchar(64)[]`, job.WorkspaceID, importIDFromJob(t, job)).Scan(&dispatchOutcomes); err != nil {
		t.Fatal(err)
	}
	if dispatchOutcomes != 3 {
		t.Fatalf("versioned dispatch outcomes = %d, want 3", dispatchOutcomes)
	}
	var supportedMappings int
	if err := harness.db.QueryRow(`
		SELECT count(*)
		FROM open_aspm.observation_normalizations AS normalization
		JOIN open_aspm.observations AS observation
		  ON observation.workspace_id = normalization.workspace_id
		 AND observation.id = normalization.observation_id
		JOIN open_aspm.scans AS scan
		  ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2
		  AND normalization.normalizer_name = 'sarif'
		  AND normalization.normalizer_version = '1'
		  AND normalization.category = 'unknown'
		  AND (
		    (observation.source_level = 'warning' AND normalization.severity = 'medium') OR
		    (observation.source_level = 'note' AND normalization.severity = 'low') OR
		    (observation.source_level IS NULL AND normalization.severity = 'unknown')
		  )`, job.WorkspaceID, importIDFromJob(t, job)).Scan(&supportedMappings); err != nil {
		t.Fatal(err)
	}
	if supportedMappings != 3 {
		t.Fatalf("supported source-to-normalized severity mappings = %d, want 3", supportedMappings)
	}
	var nonUnknown int
	if err := harness.db.QueryRow(`
		SELECT count(*) FROM open_aspm.scans
		WHERE workspace_id = $1 AND import_id = $2
		  AND (result <> 'unknown' OR completeness <> 'unknown')`,
		job.WorkspaceID, importIDFromJob(t, job),
	).Scan(&nonUnknown); err != nil {
		t.Fatal(err)
	}
	if nonUnknown != 0 {
		t.Fatalf("scans with invented outcome or coverage = %d", nonUnknown)
	}
	var inventedContext int
	if err := harness.db.QueryRow(`
		SELECT count(*) FROM open_aspm.scans AS scan
		JOIN open_aspm.scan_scopes AS scope
		  ON scope.workspace_id = scan.workspace_id AND scope.scan_id = scan.id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2
		  AND (scan.analysis_context_import_id IS NOT NULL OR scope.analysis_kind <> 'unknown')`,
		job.WorkspaceID, importIDFromJob(t, job),
	).Scan(&inventedContext); err != nil {
		t.Fatal(err)
	}
	if inventedContext != 0 {
		t.Fatalf("scans with invented analysis context = %d", inventedContext)
	}
	if _, err := harness.db.Exec(`
		UPDATE open_aspm.import_parse_outputs SET warnings_truncated = true
		WHERE workspace_id = $1 AND import_id = $2`, job.WorkspaceID, importIDFromJob(t, job)); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable parser output")
	}
	if _, err := harness.db.Exec(`
		UPDATE open_aspm.observation_normalizations SET severity = 'critical'
		WHERE workspace_id = $1`, job.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable normalization output")
	}
	if _, err := harness.db.Exec(`
		UPDATE open_aspm.observation_correlation_outcomes SET state = 'correlated'
		WHERE workspace_id = $1`, job.WorkspaceID); err == nil {
		t.Fatal("runtime role unexpectedly updated immutable correlation output")
	}
}

func TestImportProcessorAppliesAcceptedContextToEveryRun(t *testing.T) {
	harness := openProcessorHarness(t)
	report, err := os.ReadFile("../../../testdata/sarif/valid/representative.sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	analysisContext := &ingestion.AnalysisContextRequest{
		AnalysisKind: ingestion.AnalysisKindSAST,
		Target: ingestion.AnalysisTargetRequest{
			Type: ingestion.AnalysisTargetRepository, ID: "repository-a",
		},
	}
	job := harness.createImportJobWithContext(t, "mapped-context", report, analysisContext)
	if _, err := harness.ownerDB.Exec(`
		UPDATE open_aspm.application_repository_relationships
		SET valid_until = clock_timestamp()
		WHERE workspace_id = 'workspace-a' AND id = 'relationship-a'
		  AND valid_until IS NULL`); err != nil {
		t.Fatal(err)
	}
	historicalRequest := ingestion.ReserveRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		IdempotencyKey:  "processor-reserve-mapped-context",
		ReportFormat:    ingestion.ReportFormat{Name: sarif.Format, Version: sarif.FormatVersion},
		AnalysisContext: analysisContext,
	}
	historical, err := harness.service.Reserve(context.Background(), historicalRequest)
	if err != nil || historical.Created || historical.Import.ID != importIDFromJob(t, job) {
		t.Fatalf("historical Reserve() replay = (%+v, %v)", historical, err)
	}
	futureRequest := ingestion.ReserveRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		IdempotencyKey:  "processor-reserve-after-relationship-end",
		ReportFormat:    ingestion.ReportFormat{Name: sarif.Format, Version: sarif.FormatVersion},
		AnalysisContext: analysisContext,
	}
	if _, err := harness.service.Reserve(context.Background(), futureRequest); !errors.Is(err, ingestion.ErrAnalysisTargetNotFound) {
		t.Fatalf("Reserve() after relationship end error = %v, want ErrAnalysisTargetNotFound", err)
	}
	if outcome := harness.processor.Handle(context.Background(), job); outcome.Kind != jobqueue.OutcomeSucceeded {
		t.Fatalf("Handle() = %+v, want success", outcome)
	}
	importID := importIDFromJob(t, job)
	var mappedScans int
	if err := harness.db.QueryRow(`
		SELECT count(*) FROM open_aspm.scans AS scan
		JOIN open_aspm.scan_scopes AS scope
		  ON scope.workspace_id = scan.workspace_id AND scope.scan_id = scan.id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2
		  AND scan.analysis_context_import_id = scan.import_id
		  AND scope.analysis_kind = 'sast'`, job.WorkspaceID, importID,
	).Scan(&mappedScans); err != nil {
		t.Fatal(err)
	}
	if mappedScans != 2 {
		t.Fatalf("context-mapped scans = %d, want 2", mappedScans)
	}
	var outcomes int
	if err := harness.db.QueryRow(`
		SELECT count(*) FROM open_aspm.observation_correlation_outcomes AS outcome
		JOIN open_aspm.observations AS observation
		  ON observation.workspace_id = outcome.workspace_id
		 AND observation.id = outcome.observation_id
		JOIN open_aspm.scans AS scan
		  ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2
		  AND outcome.algorithm = 'correlation-dispatch'
		  AND outcome.algorithm_version = '2'
		  AND outcome.reason_codes = ARRAY[
		    'scanner_family_unknown', 'source_context_unknown'
		  ]::varchar(64)[]`, job.WorkspaceID, importID,
	).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if outcomes != 3 {
		t.Fatalf("context-aware uncorrelated outcomes = %d, want 3", outcomes)
	}
}

func TestImportProcessorReplaysCorrelationAfterCompletionFailure(t *testing.T) {
	harness := openProcessorHarness(t)
	report, err := os.ReadFile("../../../testdata/sarif/valid/representative.sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	job := harness.createImportJob(t, "completion-retry", report)
	flakyStore := &failOnceCompletionStore{processingStore: harness.store}
	processor := harness.newProcessor(t, flakyStore)

	first := processor.Handle(context.Background(), job)
	if first.Kind != jobqueue.OutcomeRetryable || first.Code != "database-unavailable" {
		t.Fatalf("first Handle() = %+v, want retryable completion failure", first)
	}
	if count := harness.correlationOutcomeCount(t, job); count != 3 {
		t.Fatalf("correlation outcomes after completion failure = %d, want 3", count)
	}

	second := processor.Handle(context.Background(), job)
	if second.Kind != jobqueue.OutcomeSucceeded {
		t.Fatalf("second Handle() = %+v, want success", second)
	}
	if count := harness.correlationOutcomeCount(t, job); count != 3 {
		t.Fatalf("correlation outcomes after replay = %d, want 3", count)
	}
}

func TestImportProcessorRecordsSanitizedPermanentFailure(t *testing.T) {
	harness := openProcessorHarness(t)
	job := harness.createImportJob(t, "malformed", []byte(`{"version":"2.1.0","runs":[`))
	outcome := harness.processor.Handle(context.Background(), job)
	if outcome.Kind != jobqueue.OutcomePermanent || outcome.Code != "sarif-malformed-json" {
		t.Fatalf("Handle() = %+v, want permanent malformed SARIF", outcome)
	}
	var importState, operationState, failureCode, failureTitle string
	var failureDetail sql.NullString
	if err := harness.db.QueryRow(`
		SELECT imp.state, op.state, op.failure_code, op.failure_title, op.failure_detail
		FROM open_aspm.imports AS imp
		JOIN open_aspm.operations AS op
		  ON op.workspace_id = imp.workspace_id AND op.import_id = imp.id
		WHERE imp.workspace_id = $1 AND imp.id = $2`, job.WorkspaceID, importIDFromJob(t, job),
	).Scan(&importState, &operationState, &failureCode, &failureTitle, &failureDetail); err != nil {
		t.Fatal(err)
	}
	if importState != "failed" || operationState != "failed" || failureCode != outcome.Code ||
		failureTitle != "The SARIF report could not be processed" || failureDetail.Valid {
		t.Fatalf("failure = import %q operation %q code %q title %q detail %+v",
			importState, operationState, failureCode, failureTitle, failureDetail)
	}
}

func TestImportProcessorDoesNotCrossWorkspaceBoundary(t *testing.T) {
	harness := openProcessorHarness(t)
	job := harness.createImportJob(t, "workspace-boundary", []byte(`{"version":"2.1.0","runs":[]}`))
	job.WorkspaceID = "workspace-b"
	outcome := harness.processor.Handle(context.Background(), job)
	if outcome.Kind != jobqueue.OutcomePermanent || outcome.Code != "processing-target-not-found" {
		t.Fatalf("cross-workspace Handle() = %+v", outcome)
	}
	var operationState string
	if err := harness.db.QueryRow(`
		SELECT state FROM open_aspm.operations WHERE workspace_id = 'workspace-a' AND id = $1`,
		job.OperationID,
	).Scan(&operationState); err != nil {
		t.Fatal(err)
	}
	if operationState != "queued" {
		t.Fatalf("cross-workspace attempt changed operation to %q", operationState)
	}
}

type processorHarness struct {
	db           *sql.DB
	ownerDB      *sql.DB
	service      *ingestion.Service
	processor    *Processor
	store        *ingestion.PostgresStore
	observations *finding.PostgresStore
	correlations *correlation.PostgresStore
	blobs        *filesystem.Store
	parser       *sarif.Parser
	authorizer   ingestion.Authorizer
	config       Config
}

func openProcessorHarness(t *testing.T) *processorHarness {
	t.Helper()
	adminURL := os.Getenv("OPEN_ASPM_TEST_DATABASE_ADMIN_URL")
	if adminURL == "" {
		t.Skip("OPEN_ASPM_TEST_DATABASE_ADMIN_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("connect to test PostgreSQL: %v", err)
	}

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	databaseName := "open_aspm_processor_" + suffix
	ownerRole := "open_aspm_processor_owner_" + suffix
	runtimeRole := "open_aspm_processor_runtime_" + suffix
	password := "integration-test-only"
	databaseIdentifier := pgx.Identifier{databaseName}.Sanitize()
	ownerIdentifier := pgx.Identifier{ownerRole}.Sanitize()
	runtimeIdentifier := pgx.Identifier{runtimeRole}.Sanitize()
	for _, role := range []string{ownerIdentifier, runtimeIdentifier} {
		if _, err := admin.ExecContext(ctx, fmt.Sprintf(
			"CREATE ROLE %s LOGIN PASSWORD 'integration-test-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION",
			role,
		)); err != nil {
			t.Fatalf("create test role: %v", err)
		}
	}
	if _, err := admin.ExecContext(ctx, fmt.Sprintf(
		"CREATE DATABASE %s OWNER %s", databaseIdentifier, ownerIdentifier,
	)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", databaseIdentifier))
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP ROLE IF EXISTS %s", runtimeIdentifier))
		_, _ = admin.ExecContext(cleanupCtx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ownerIdentifier))
	})

	ownerURL := processorDatabaseURL(t, adminURL, databaseName, ownerRole, password)
	migrator, err := database.Open(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatal(err)
	}
	ownerDB, err := sql.Open("pgx", ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })
	for _, workspaceID := range []string{"workspace-a", "workspace-b"} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO open_aspm.workspaces (id) VALUES ($1)`, workspaceID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ownerDB.ExecContext(ctx, `
		INSERT INTO open_aspm.applications (workspace_id, id)
		VALUES ('workspace-a', 'application-a'), ('workspace-b', 'application-b')`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `
		INSERT INTO open_aspm.repositories (
			workspace_id, id, display_name, created_by_principal_id, created_at, updated_at
		) VALUES (
			'workspace-a', 'repository-a', 'repository-a', 'principal-a',
			clock_timestamp(), clock_timestamp()
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `
		INSERT INTO open_aspm.application_repository_relationships (
			workspace_id, id, application_id, repository_id,
			linked_by_principal_id, valid_from
		) VALUES (
			'workspace-a', 'relationship-a', 'application-a', 'repository-a',
			'principal-a', clock_timestamp()
		)`); err != nil {
		t.Fatal(err)
	}
	grants := []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA open_aspm TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.workspaces, open_aspm.applications TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT, UPDATE ON open_aspm.imports, open_aspm.raw_artifacts, open_aspm.operations TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.import_create_idempotency, open_aspm.import_complete_idempotency, open_aspm.jobs TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.scans, open_aspm.scan_scopes TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.observations, open_aspm.observation_locations, open_aspm.observation_fingerprints TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.observation_normalizations TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.observation_correlation_outcomes TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.import_parse_outputs, open_aspm.import_parse_warnings TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT ON open_aspm.application_repository_relationships TO %s", runtimeIdentifier),
		fmt.Sprintf("GRANT SELECT, INSERT ON open_aspm.import_analysis_contexts TO %s", runtimeIdentifier),
	}
	for _, grant := range grants {
		if _, err := ownerDB.ExecContext(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}

	runtimeURL := processorDatabaseURL(t, adminURL, databaseName, runtimeRole, password)
	db, err := sql.Open("pgx", runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(20)
	store, err := ingestion.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	observationStore, err := finding.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	correlationStore, err := correlation.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blobs.Close() })
	authorizer := allowProcessorAuthorizer{}
	catalogStore, err := catalog.NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := catalog.NewResolutionService(catalogStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := ingestion.NewService(store, blobs, authorizer, targets, ingestion.Config{
		MaxUploadBytes: 100 << 20, UploadReservationTTL: 30 * time.Minute,
		UploadTimeout: time.Minute, IdempotencyRetention: 24 * time.Hour,
		StorageBackend: "filesystem-test", ProcessMaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := sarif.New(sarif.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	harness := &processorHarness{
		db: db, ownerDB: ownerDB, service: service, store: store, observations: observationStore,
		correlations: correlationStore, blobs: blobs, parser: parser, authorizer: authorizer,
		config: Config{
			StorageBackend: "filesystem-test", ProcessingTimeout: time.Minute, RetryMaximumAge: time.Hour,
		},
	}
	harness.processor = harness.newProcessor(t, store)
	return harness
}

func (harness *processorHarness) newProcessor(t *testing.T, store processingStore) *Processor {
	t.Helper()
	processor, err := New(store, harness.store, harness.observations, harness.blobs, harness.parser,
		sarifnormalization.New(), harness.correlations, harness.authorizer, harness.config)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func (harness *processorHarness) correlationOutcomeCount(t *testing.T, job jobqueue.Job) int {
	t.Helper()
	var count int
	err := harness.db.QueryRow(`
		SELECT count(*)
		FROM open_aspm.observation_correlation_outcomes AS outcome
		JOIN open_aspm.observations AS observation
		  ON observation.workspace_id = outcome.workspace_id
		 AND observation.id = outcome.observation_id
		JOIN open_aspm.scans AS scan
		  ON scan.workspace_id = observation.workspace_id AND scan.id = observation.scan_id
		WHERE scan.workspace_id = $1 AND scan.import_id = $2`,
		job.WorkspaceID, importIDFromJob(t, job),
	).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

type failOnceCompletionStore struct {
	processingStore
	failed bool
}

func (store *failOnceCompletionStore) CompleteProcessing(
	ctx context.Context,
	identity ingestion.ProcessingIdentity,
	result ingestion.ProcessingResult,
	finishedAt time.Time,
) error {
	if !store.failed {
		store.failed = true
		return errors.New("synthetic completion failure")
	}
	return store.processingStore.CompleteProcessing(ctx, identity, result, finishedAt)
}

func (harness *processorHarness) createImportJob(t *testing.T, suffix string, report []byte) jobqueue.Job {
	return harness.createImportJobWithContext(t, suffix, report, nil)
}

func (harness *processorHarness) createImportJobWithContext(
	t *testing.T,
	suffix string,
	report []byte,
	analysisContext *ingestion.AnalysisContextRequest,
) jobqueue.Job {
	t.Helper()
	ctx := context.Background()
	request := ingestion.ReserveRequest{
		PrincipalID: "principal-a", WorkspaceID: "workspace-a", ApplicationID: "application-a",
		IdempotencyKey:  "processor-reserve-" + suffix,
		ReportFormat:    ingestion.ReportFormat{Name: sarif.Format, Version: sarif.FormatVersion},
		AnalysisContext: analysisContext,
	}
	reservation, err := harness.service.Reserve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.service.Upload(ctx, ingestion.UploadRequest{
		PrincipalID: request.PrincipalID, WorkspaceID: request.WorkspaceID,
		ApplicationID: request.ApplicationID, ImportID: reservation.Import.ID,
		Content: bytes.NewReader(report),
	}); err != nil {
		t.Fatal(err)
	}
	completion, err := harness.service.Complete(ctx, ingestion.CompleteRequest{
		PrincipalID: request.PrincipalID, WorkspaceID: request.WorkspaceID,
		ApplicationID: request.ApplicationID, ImportID: reservation.Import.ID,
		IdempotencyKey: "processor-complete-" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(struct {
		ImportID string `json:"import_id"`
	}{ImportID: reservation.Import.ID})
	return jobqueue.Job{
		ID: "job-" + suffix, WorkspaceID: request.WorkspaceID,
		OperationID: completion.Operation.ID, InitiatingPrincipalID: request.PrincipalID,
		SystemCapability: ingestion.CapabilityImportsProcess,
		Queue:            "ingestion", Kind: ingestion.ImportProcessJobKind,
		SchemaVersion: ingestion.ImportProcessJobSchema, Payload: payload,
		AttemptCount: 1, MaxAttempts: 3, CreatedAt: time.Now().UTC(),
	}
}

func importIDFromJob(t *testing.T, job jobqueue.Job) string {
	t.Helper()
	var payload struct {
		ImportID string `json:"import_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.ImportID
}

func processorDatabaseURL(t *testing.T, baseURL, databaseName, user, password string) string {
	t.Helper()
	config, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.Path = "/" + databaseName
	config.User = url.UserPassword(user, password)
	return config.String()
}

type allowProcessorAuthorizer struct{}

func (allowProcessorAuthorizer) Authorize(context.Context, ingestion.AuthorizationRequest) error {
	return nil
}
