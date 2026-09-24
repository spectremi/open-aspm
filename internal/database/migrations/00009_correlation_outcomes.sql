-- +goose Up
CREATE TABLE open_aspm.observation_correlation_outcomes (
    workspace_id varchar(128) NOT NULL,
    observation_id varchar(128) NOT NULL,
    normalizer_name varchar(64) NOT NULL,
    normalizer_version varchar(64) NOT NULL,
    algorithm varchar(64) NOT NULL,
    algorithm_version varchar(64) NOT NULL,
    state varchar(32) NOT NULL,
    reason_codes varchar(64)[] NOT NULL,
    evaluated_at timestamptz NOT NULL,
    record_fingerprint bytea NOT NULL,
    PRIMARY KEY (
        workspace_id, observation_id, algorithm, algorithm_version
    ),
    CONSTRAINT observation_correlation_outcomes_normalization_fk
        FOREIGN KEY (
            workspace_id, observation_id, normalizer_name, normalizer_version
        )
        REFERENCES open_aspm.observation_normalizations (
            workspace_id, observation_id, normalizer_name, normalizer_version
        ),
    CONSTRAINT observation_correlation_outcomes_algorithm_format CHECK (
        algorithm ~ '^[a-z][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT observation_correlation_outcomes_version_length CHECK (
        length(algorithm_version) BETWEEN 1 AND 64
    ),
    CONSTRAINT observation_correlation_outcomes_state_known CHECK (
        state = 'uncorrelated'
    ),
    CONSTRAINT observation_correlation_outcomes_reasons_canonical CHECK (
        cardinality(reason_codes) BETWEEN 1 AND 9 AND
        reason_codes = array_remove(ARRAY[
            CASE WHEN 'target_identity_unknown' = ANY(reason_codes)
                THEN 'target_identity_unknown' END,
            CASE WHEN 'analysis_kind_unknown' = ANY(reason_codes)
                THEN 'analysis_kind_unknown' END,
            CASE WHEN 'scanner_family_unknown' = ANY(reason_codes)
                THEN 'scanner_family_unknown' END,
            CASE WHEN 'rule_identity_unknown' = ANY(reason_codes)
                THEN 'rule_identity_unknown' END,
            CASE WHEN 'package_identity_unknown' = ANY(reason_codes)
                THEN 'package_identity_unknown' END,
            CASE WHEN 'vulnerability_identity_unknown' = ANY(reason_codes)
                THEN 'vulnerability_identity_unknown' END,
            CASE WHEN 'location_identity_unknown' = ANY(reason_codes)
                THEN 'location_identity_unknown' END,
            CASE WHEN 'source_context_unknown' = ANY(reason_codes)
                THEN 'source_context_unknown' END,
            CASE WHEN 'source_context_unsafe' = ANY(reason_codes)
                THEN 'source_context_unsafe' END
        ]::varchar(64)[], NULL)
    ),
    CONSTRAINT observation_correlation_outcomes_fingerprint_length CHECK (
        octet_length(record_fingerprint) = 32
    )
);

CREATE INDEX observation_correlation_outcomes_review_idx
    ON open_aspm.observation_correlation_outcomes (
        workspace_id, state, evaluated_at, observation_id
    );
