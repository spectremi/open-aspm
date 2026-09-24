-- +goose Up
CREATE TABLE open_aspm.import_analysis_contexts (
    workspace_id varchar(128) NOT NULL,
    import_id varchar(128) NOT NULL,
    application_id varchar(128) NOT NULL,
    analysis_kind varchar(64) NOT NULL,
    target_type varchar(64) NOT NULL,
    target_id varchar(128) NOT NULL,
    target_relationship_id varchar(128) NOT NULL,
    assertion_source varchar(64) NOT NULL,
    asserted_by_principal_id varchar(128) NOT NULL,
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, import_id),
    CONSTRAINT import_analysis_contexts_import_fk
        FOREIGN KEY (workspace_id, import_id, application_id)
        REFERENCES open_aspm.imports (workspace_id, id, application_id),
    CONSTRAINT import_analysis_contexts_repository_relationship_fk
        FOREIGN KEY (
            workspace_id, application_id, target_id, target_relationship_id
        ) REFERENCES open_aspm.application_repository_relationships (
            workspace_id, application_id, repository_id, id
        ),
    CONSTRAINT import_analysis_contexts_analysis_kind_known
        CHECK (analysis_kind = 'sast'),
    CONSTRAINT import_analysis_contexts_target_type_known
        CHECK (target_type = 'repository'),
    CONSTRAINT import_analysis_contexts_assertion_source_known
        CHECK (assertion_source = 'api_client'),
    CONSTRAINT import_analysis_contexts_principal_length
        CHECK (length(asserted_by_principal_id) BETWEEN 3 AND 128)
);

ALTER TABLE open_aspm.scans
    ADD COLUMN analysis_context_import_id varchar(128),
    ADD CONSTRAINT scans_analysis_context_same_import CHECK (
        analysis_context_import_id IS NULL OR analysis_context_import_id = import_id
    ),
    ADD CONSTRAINT scans_analysis_context_fk
        FOREIGN KEY (workspace_id, analysis_context_import_id)
        REFERENCES open_aspm.import_analysis_contexts (workspace_id, import_id);
