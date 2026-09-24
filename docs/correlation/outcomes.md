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

Version-one reason codes are stored once in canonical order:

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

## Deliberately deferred

This slice does not create Findings or correlation fingerprints. Current SARIF
imports provide only an Application identity and conservatively retain unknown
scanner family and analysis kind. Treating an untrusted artifact URI as a
Repository identity would violate ADR-0002 and ADR-0007.

A later contract must provide an authorized stable target identity before a
supported algorithm can create a fingerprint and attach an Observation to a
Finding. The worker and authorized query API are not wired to these outcomes
yet.

See [ADR-0007](../adr/0007-finding-identity-and-fingerprint-versioning.md) for
the identity decision and [SARIF normalization](../normalization/sarif.md) for
the current normalized input boundary.
