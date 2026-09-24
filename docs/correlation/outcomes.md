# Correlation outcomes

Open ASPM records an explicit immutable outcome when a versioned correlation
algorithm cannot construct a reliable Finding fingerprint for an Observation.
This prevents missing identity inputs from becoming either a false merge or
hidden evidence.

## Implemented persistence

The first stored outcome is:

```text
state: uncorrelated
key: workspace + Observation + algorithm + algorithm version
source: one immutable Observation normalization
```

Every outcome retains the normalizer name and version, algorithm name and
version, canonical reason codes, evaluation time, and a deterministic record
fingerprint. Evaluation time is audit metadata and does not change replay
identity. Exact replay returns the originally stored outcome. Reusing the same
key for different inputs is a conflict.

Supported reason codes are stored once in canonical order:

```text
target_identity_unknown
analysis_kind_unknown
scanner_family_unknown
rule_identity_unknown
package_identity_unknown
vulnerability_identity_unknown
location_identity_unknown
source_context_unknown
source_context_unsafe
```

The database constrains the allowed values, uniqueness, and ordering. The
runtime role requires only `SELECT` and `INSERT`; outcomes cannot be updated in
place.

The import worker invokes `correlation-dispatch` after persisting each SARIF
normalization. This dispatch step requires a stable catalog target identity and
a known analysis kind before selecting a fingerprint family. An Import without
accepted analysis context retains version `1` and deterministically records:

```text
target_identity_unknown
analysis_kind_unknown
```

It does not add scanner-, rule-, package-, vulnerability-, location-, or
source-context reasons before an analysis family has been selected, because
those inputs are not required by every fingerprint family.

When the internal Import model contains an accepted `sast + repository`
context, dispatch uses version `2` and removes only the target and analysis
blockers. The current SARIF adapter has no server-owned scanner-family mapping
or safe stable source context, so it deterministically records:

```text
scanner_family_unknown
source_context_unknown
```

Version `1` remains selected for unmapped Imports so an in-flight job retry
does not produce a second interpretation after deployment. Version `2` is
selected only for the new mapped input domain. Historical outcomes remain
immutable.

## Deliberately deferred

This slice does not create Findings or correlation fingerprints. Mapped SARIF
imports can provide an authorized Repository identity and SAST analysis kind,
but still conservatively retain unknown scanner family and source context.
Treating an untrusted artifact URI as either identity would violate ADR-0002
and ADR-0007.

A later slice must provide a server-owned scanner-family mapping and a safe,
stable source-context rule before the SAST family can create a fingerprint and
attach an Observation to a Finding. The authorized query API is not wired to
these outcomes yet.

See [ADR-0007](../adr/0007-finding-identity-and-fingerprint-versioning.md) for
the identity decision and [SARIF normalization](../normalization/sarif.md) for
the current normalized input boundary.
