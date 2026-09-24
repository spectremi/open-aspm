# ADR-0008: Import analysis context and catalog target attribution

- **Status:** Proposed
- **Date:** 2026-09-24
- **Owners:** Open ASPM maintainers
- **Related issues:** MVP-005 in [CONTRIBUTOR_TASKS.md](../../CONTRIBUTOR_TASKS.md)
- **Supersedes:** None
- **Superseded by:** None

## Context

The current `createImport` contract requires an Application ID and a report
format. The implemented SARIF worker therefore knows which Application owns an
Import, but it does not know the stable Repository, Component, Artifact, or
Deployment assessed by a scanner. It also retains the scan analysis kind as
`unknown`.

ADR-0007 requires a stable catalog target identity and an analysis kind before
a fingerprint family can run. An Application is not an interchangeable
substitute: ADR-0002 permits one Application to use multiple Repositories and
one Repository to contribute to multiple Applications. A SARIF artifact URI,
repository URL, checkout path, display name, or provider locator is mutable and
cannot safely authorize or select a catalog identity.

The current worker consequently records `correlation-dispatch/1` as
`uncorrelated` with `target_identity_unknown` and `analysis_kind_unknown`.
This is correct, but Open ASPM needs an integration-agnostic way for an
authorized CI client or agent to attribute evidence to a pre-existing catalog
target without allowing report content to create or merge catalog objects.

One SARIF artifact may contain multiple runs. The first implementation already
supports this and must not pretend that each run came from a separate Import.
At the same time, a single import-level declaration cannot safely describe a
mixed-target artifact.

## Decision

### 1. Import reservation may carry optional analysis context

`createImport` gains one optional object whose initial public shape is:

```yaml
analysis_context:
  analysis_kind: sast
  target:
    type: repository
    id: repo_opaque_id
```

The field is optional. Omitting it preserves the current behavior: evidence is
accepted and processed, but missing correlation inputs remain explicitly
unknown. Open ASPM does not require callers to fabricate context merely to
upload a report.

The first activated combination is exactly:

```text
analysis_kind: sast
target.type: repository
```

Additional analysis kinds or target types require explicit server support,
normal compatibility review, and correlation-family tests. A client cannot
select a parser, normalizer, correlation algorithm, or algorithm version.

### 2. The target is an existing Open ASPM catalog identity

`target.id` is an opaque, workspace-scoped Open ASPM Repository ID. It is not a
repository name, URL, path, provider ID, or digest. The target must already
exist in Catalog and have an active explicit relationship to the Application
named by the Import.

Ingestion resolves the reference through a Catalog application interface. It
does not write Catalog tables, create Repository records, attach external
identities, or infer Application relationships. Catalog remains the owner of
Repository identity and Application-to-Repository relationships.

Inline catalog creation is not part of `createImport`. Provisioning and linking
Repositories uses separately authorized Catalog operations so an ingestion
token cannot acquire catalog-mutation authority as a side effect of uploading
evidence.

### 3. Analysis context is an attributable assertion

The server records the accepted context as immutable Import provenance,
including:

```text
workspace_id
import_id
application_id
analysis_kind
target_type
target_id
target_relationship_id
assertion_source: api_client
asserted_by_principal_id
accepted_at
```

`target_relationship_id` is a durable reference to the Catalog relationship
that authorized the attribution at reservation time. The relationship history
is retained after its active interval ends.

The assertion states how the authenticated client attributed this artifact. It
does not prove scanner success, coverage completeness, repository contents, or
authority for absence. Raw report fields remain separately attributable source
evidence and cannot override the accepted context.

Each Scan derived from the Import receives a durable reference to this context.
Historical Scans retain the context accepted at reservation time even if the
Catalog relationship later ends. Ending a relationship affects new
reservations; it does not rewrite earlier evidence or correlation decisions.

### 4. One declared context applies to every run in the artifact

When `analysis_context` is present, the client asserts that it applies to every
run in the uploaded SARIF artifact. A client with runs for different targets or
analysis kinds must submit separate artifacts, or omit the context and retain
an `uncorrelated` result.

Open ASPM does not infer run-to-target mappings from artifact URIs or tool
messages. Run-specific context arrays are deferred until a demonstrated format
requires them and can define an unambiguous mapping.

### 5. Authorization and workspace isolation precede persistence

The existing `imports:create` check remains scoped to the Application. In
addition, the application service resolves the Repository using the request
workspace and verifies an active Application-to-Repository relationship before
creating the Import.

An unknown Repository, cross-workspace Repository, inactive relationship, or
Repository outside the caller's effective Application scope is concealed as a
not-found result. Possession of an opaque ID is not authorization. Database
constraints also prevent cross-workspace and cross-Application attribution.

This reference check does not grant general Catalog read access and does not
require an ingestion token to receive Catalog mutation capabilities.

### 6. Context participates in createImport idempotency

The normalized `analysis_context` is part of the `createImport` request
fingerprint. Replaying the same idempotency key with the same context returns
the original Import. Reusing the key with a different analysis kind, target
type, or target ID is an idempotency conflict.

The context is persisted before raw evidence is uploaded and is read from
authoritative Import state by the worker. It is not copied into the queue
payload, selected from environment variables, or reconstructed from report
content during a retry.

### 7. Correlation consumes context without weakening its family rules

A valid `sast + repository` context satisfies only the dispatch prerequisites
for target identity and analysis kind. It does not by itself create a Finding.
The SAST fingerprint family must still obtain every ADR-0007 input, including a
supported scanner family, rule identity, normalized relative path, and safe
stable source context.

If any family-specific input remains missing or unsafe, the Observation stays
`uncorrelated` with the applicable versioned reason codes. Context never makes
an unknown value safe, authoritative, or complete.

## Alternatives considered

### Use Application ID as the correlation target

Rejected because it would merge findings from distinct Repositories within an
Application and conflicts with ADR-0002 and the SAST inputs in ADR-0007.

### Infer Repository identity from a SARIF URI, checkout path, or filename

Rejected because those values are untrusted mutable locators. Renames, path
reuse, monorepos, and attacker-controlled report fields could split or merge
unrelated findings.

### Accept a provider ID or repository URL inline and upsert Catalog records

Rejected for the initial contract. Provider identity is meaningful only with
provider-instance scope and provenance. Inline upsert would give
`imports:create` implicit Catalog mutation authority and make conflicts or
name reuse capable of changing asset identity during evidence upload.

### Require analysis context on every Import

Rejected because evidence preservation must support scanners and customer
pipelines that cannot yet supply a mapped Catalog identity. Missing context
remains explicit uncertainty rather than making the artifact invalid.

### Put target and analysis data only in the queue payload

Rejected because queue payloads are delivery metadata, not authoritative
Import state. A retry, delayed worker, restore, or payload-version change must
not change the basis of correlation.

### Accept one context entry per SARIF run immediately

Deferred because it adds index-mapping, partial validation, and idempotency
complexity without a current requirement. Separate Imports are the explicit
initial behavior for mixed-target artifacts.

## Consequences

### Positive

- CI systems can attribute evidence without depending on GitHub, GitLab,
  Jenkins, or provider-specific environment variables.
- Correlation uses opaque Catalog identity rather than mutable locators.
- Existing unmapped ingestion remains valid and visibly uncorrelated.
- Context is reproducible across worker retries and attributable to the client
  principal that supplied it.
- Catalog ownership and ingestion authorization remain separate.

### Negative and trade-offs

- A Repository and its Application relationship must be provisioned before a
  mapped Import can be reserved.
- Clients producing mixed-target SARIF must split the artifact to receive
  target-aware correlation in version one.
- An authorized client can still make an incorrect attribution claim. Open
  ASPM preserves who asserted it but cannot prove report contents came from
  that Repository solely from SARIF bytes.
- Target and analysis context unlock dispatch only; scanner-family and stable
  source-context decisions are still required before the first SAST Finding.

## Security and privacy impact

Repository IDs and relationships are sensitive workspace metadata. Resolution
is workspace-scoped and happens after principal, capability, token, and
Application scope checks. Error behavior must not reveal whether a Repository
exists in another workspace or Application.

Database foreign keys include workspace and relationship scope. Cross-workspace
tests use valid IDs from another workspace, not merely malformed values.
Workers consume the already authorized immutable context and do not treat a job
payload or report field as authorization.

Attribution can influence which Observations later support a Finding. The
asserting principal, source, time, and exact target therefore remain retained
provenance. A declaration does not make a scan authoritative for absence and
does not change technical lifecycle by itself.

Names and URLs are not required by this contract and must not be included in
errors, queue payloads, metric labels, or correlation digests. Catalog query
and mutation capabilities remain unavailable to ordinary ingestion tokens.

## Compatibility and migration

The new request field and matching Import response field are optional additive
changes to `/api/v1`. Existing clients and stored Imports continue to work.
Existing rows are not backfilled from Application IDs, filenames, SARIF URIs,
or other mutable data; their context remains absent.

A forward migration adds the minimum Catalog Repository relationship and
immutable Import context structures without rewriting released migrations.
The migration must use workspace-aware foreign keys and preserve existing
Imports. Runtime roles receive only the reads and writes required by their
owning application services.

The safe rolling-upgrade order is:

1. apply the additive schema migration;
2. deploy workers that understand absent and present context;
3. deploy or enable servers that accept the new request field; and
4. enable clients to send it.

An older worker may not silently mark a context-aware operation successful
while omitting the required dispatch behavior. Feature enablement therefore
waits until compatible workers are available.

## Verification

Tests must prove:

- omission of context retains both dispatch-unknown reasons;
- a valid `sast + repository` context removes only the target and analysis
  dispatch blockers;
- missing family-specific inputs remain explicitly `uncorrelated`;
- context changes participate in idempotency conflicts;
- concurrent identical reservations converge on one immutable context;
- cross-workspace, unrelated-Application, inactive, and unauthorized
  Repository references are denied without existence disclosure;
- report fields cannot override the accepted target or analysis kind;
- every run in a multi-run artifact receives the same declared context;
- retry after partial processing reuses the stored context without duplicate
  effects; and
- ending a Catalog relationship does not rewrite historical Imports, Scans,
  Observations, outcomes, or Findings.

## Open questions

- What is the smallest public Catalog API and capability set for manually
  provisioning and linking a Repository before provider connectors exist?
- Which server-owned mapping establishes scanner family for the first SAST
  adapter without trusting arbitrary report text?
- Which SARIF partial fingerprint or syntax-derived value is safe and stable
  enough to serve as SAST source context version one?
- When a real format demonstrates a need for mixed-target artifacts, what
  source identifier can map run-specific contexts without relying only on
  array position?
