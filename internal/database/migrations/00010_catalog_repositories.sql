-- +goose Up
CREATE TABLE open_aspm.repositories (
    workspace_id varchar(128) NOT NULL,
    id varchar(128) NOT NULL,
    display_name varchar(255) NOT NULL,
    created_by_principal_id varchar(128) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, id),
    CONSTRAINT repositories_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES open_aspm.workspaces (id),
    CONSTRAINT repositories_id_length CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT repositories_display_name_length
        CHECK (length(display_name) BETWEEN 1 AND 255),
    CONSTRAINT repositories_principal_id_length
        CHECK (length(created_by_principal_id) BETWEEN 3 AND 128),
    CONSTRAINT repositories_updated_at_valid CHECK (updated_at >= created_at)
);

CREATE TABLE open_aspm.application_repository_relationships (
    workspace_id varchar(128) NOT NULL,
    id varchar(128) NOT NULL,
    application_id varchar(128) NOT NULL,
    repository_id varchar(128) NOT NULL,
    linked_by_principal_id varchar(128) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    PRIMARY KEY (workspace_id, id),
    CONSTRAINT application_repository_relationships_identity_unique
        UNIQUE (workspace_id, application_id, repository_id, id),
    CONSTRAINT application_repository_relationships_application_fk
        FOREIGN KEY (workspace_id, application_id)
        REFERENCES open_aspm.applications (workspace_id, id),
    CONSTRAINT application_repository_relationships_repository_fk
        FOREIGN KEY (workspace_id, repository_id)
        REFERENCES open_aspm.repositories (workspace_id, id),
    CONSTRAINT application_repository_relationships_id_length
        CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT application_repository_relationships_principal_length
        CHECK (length(linked_by_principal_id) BETWEEN 3 AND 128),
    CONSTRAINT application_repository_relationships_interval_valid
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE UNIQUE INDEX application_repository_relationships_active_unique
    ON open_aspm.application_repository_relationships (
        workspace_id, application_id, repository_id
    )
    WHERE valid_until IS NULL;

CREATE TABLE open_aspm.repository_create_idempotency (
    workspace_id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    api_major_version smallint NOT NULL,
    operation varchar(64) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_fingerprint bytea NOT NULL,
    repository_id varchar(128) NOT NULL,
    completed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (
        workspace_id, principal_id, api_major_version, operation, idempotency_key
    ),
    CONSTRAINT repository_create_idempotency_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES open_aspm.workspaces (id),
    CONSTRAINT repository_create_idempotency_repository_fk
        FOREIGN KEY (workspace_id, repository_id)
        REFERENCES open_aspm.repositories (workspace_id, id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT repository_create_idempotency_principal_length
        CHECK (length(principal_id) BETWEEN 3 AND 128),
    CONSTRAINT repository_create_idempotency_api_version_positive
        CHECK (api_major_version > 0),
    CONSTRAINT repository_create_idempotency_operation_format
        CHECK (operation ~ '^[a-z][a-z0-9._:-]{0,63}$'),
    CONSTRAINT repository_create_idempotency_key_format
        CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT repository_create_idempotency_fingerprint_length
        CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT repository_create_idempotency_retention CHECK (
        expires_at >= completed_at + interval '24 hours'
    )
);
