-- +goose Up
CREATE TABLE open_aspm.principals (
    id varchar(128) PRIMARY KEY,
    kind varchar(32) NOT NULL,
    state varchar(32) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT principals_id_length CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT principals_kind_known
        CHECK (kind IN ('user', 'service_account', 'agent', 'system')),
    CONSTRAINT principals_state_known CHECK (state IN ('active', 'suspended')),
    CONSTRAINT principals_updated_at_valid CHECK (updated_at >= created_at)
);

CREATE TABLE open_aspm.workspace_memberships (
    workspace_id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    state varchar(32) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    PRIMARY KEY (workspace_id, principal_id),
    CONSTRAINT workspace_memberships_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES open_aspm.workspaces (id),
    CONSTRAINT workspace_memberships_principal_fk
        FOREIGN KEY (principal_id) REFERENCES open_aspm.principals (id),
    CONSTRAINT workspace_memberships_state_known
        CHECK (state IN ('invited', 'active', 'suspended', 'removed')),
    CONSTRAINT workspace_memberships_interval_valid
        CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT workspace_memberships_removed_closed
        CHECK (state <> 'removed' OR valid_until IS NOT NULL)
);

CREATE TABLE open_aspm.service_accounts (
    workspace_id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    display_name varchar(255) NOT NULL,
    owner_principal_id varchar(128),
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, principal_id),
    CONSTRAINT service_accounts_principal_unique UNIQUE (principal_id),
    CONSTRAINT service_accounts_membership_fk
        FOREIGN KEY (workspace_id, principal_id)
        REFERENCES open_aspm.workspace_memberships (workspace_id, principal_id),
    CONSTRAINT service_accounts_owner_membership_fk
        FOREIGN KEY (workspace_id, owner_principal_id)
        REFERENCES open_aspm.workspace_memberships (workspace_id, principal_id),
    CONSTRAINT service_accounts_display_name_length
        CHECK (length(display_name) BETWEEN 1 AND 255),
    CONSTRAINT service_accounts_expiry_valid
        CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE open_aspm.roles (
    workspace_id varchar(128) NOT NULL,
    id varchar(128) NOT NULL,
    name varchar(128) NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, id),
    CONSTRAINT roles_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES open_aspm.workspaces (id),
    CONSTRAINT roles_name_unique UNIQUE (workspace_id, name),
    CONSTRAINT roles_id_length CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT roles_name_length CHECK (length(name) BETWEEN 1 AND 128)
);

CREATE TABLE open_aspm.role_capabilities (
    workspace_id varchar(128) NOT NULL,
    role_id varchar(128) NOT NULL,
    capability varchar(128) NOT NULL,
    PRIMARY KEY (workspace_id, role_id, capability),
    CONSTRAINT role_capabilities_role_fk
        FOREIGN KEY (workspace_id, role_id)
        REFERENCES open_aspm.roles (workspace_id, id),
    CONSTRAINT role_capabilities_capability_format
        CHECK (capability ~ '^[a-z][a-z0-9._:-]{0,127}$')
);

CREATE TABLE open_aspm.role_bindings (
    workspace_id varchar(128) NOT NULL,
    id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    role_id varchar(128) NOT NULL,
    scope_type varchar(32) NOT NULL,
    application_id varchar(128),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    PRIMARY KEY (workspace_id, id),
    CONSTRAINT role_bindings_membership_fk
        FOREIGN KEY (workspace_id, principal_id)
        REFERENCES open_aspm.workspace_memberships (workspace_id, principal_id),
    CONSTRAINT role_bindings_role_fk
        FOREIGN KEY (workspace_id, role_id)
        REFERENCES open_aspm.roles (workspace_id, id),
    CONSTRAINT role_bindings_application_fk
        FOREIGN KEY (workspace_id, application_id)
        REFERENCES open_aspm.applications (workspace_id, id),
    CONSTRAINT role_bindings_id_length CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT role_bindings_scope_valid CHECK (
        (scope_type = 'workspace' AND application_id IS NULL) OR
        (scope_type = 'application' AND application_id IS NOT NULL)
    ),
    CONSTRAINT role_bindings_interval_valid
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE UNIQUE INDEX role_bindings_active_workspace_unique
    ON open_aspm.role_bindings (workspace_id, principal_id, role_id)
    WHERE scope_type = 'workspace' AND valid_until IS NULL;

CREATE UNIQUE INDEX role_bindings_active_application_unique
    ON open_aspm.role_bindings (workspace_id, principal_id, role_id, application_id)
    WHERE scope_type = 'application' AND valid_until IS NULL;

CREATE TABLE open_aspm.api_tokens (
    workspace_id varchar(128) NOT NULL,
    id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    token_prefix varchar(32) NOT NULL,
    verifier bytea NOT NULL,
    verifier_key_id varchar(64) NOT NULL,
    application_scope_mode varchar(32) NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (workspace_id, id),
    CONSTRAINT api_tokens_prefix_unique UNIQUE (token_prefix),
    CONSTRAINT api_tokens_membership_fk
        FOREIGN KEY (workspace_id, principal_id)
        REFERENCES open_aspm.workspace_memberships (workspace_id, principal_id),
    CONSTRAINT api_tokens_identity_unique
        UNIQUE (workspace_id, id, principal_id),
    CONSTRAINT api_tokens_id_length CHECK (length(id) BETWEEN 3 AND 128),
    CONSTRAINT api_tokens_prefix_format
        CHECK (token_prefix ~ '^oaspm_[a-z2-7]{20}$'),
    CONSTRAINT api_tokens_verifier_length CHECK (octet_length(verifier) = 32),
    CONSTRAINT api_tokens_verifier_key_id_format
        CHECK (verifier_key_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    CONSTRAINT api_tokens_application_scope_known
        CHECK (application_scope_mode IN ('workspace', 'explicit')),
    CONSTRAINT api_tokens_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT api_tokens_last_used_valid
        CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CONSTRAINT api_tokens_revocation_valid
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE TABLE open_aspm.api_token_capabilities (
    workspace_id varchar(128) NOT NULL,
    token_id varchar(128) NOT NULL,
    capability varchar(128) NOT NULL,
    PRIMARY KEY (workspace_id, token_id, capability),
    CONSTRAINT api_token_capabilities_token_fk
        FOREIGN KEY (workspace_id, token_id)
        REFERENCES open_aspm.api_tokens (workspace_id, id),
    CONSTRAINT api_token_capabilities_capability_format
        CHECK (capability ~ '^[a-z][a-z0-9._:-]{0,127}$')
);

CREATE TABLE open_aspm.api_token_application_scopes (
    workspace_id varchar(128) NOT NULL,
    token_id varchar(128) NOT NULL,
    application_id varchar(128) NOT NULL,
    PRIMARY KEY (workspace_id, token_id, application_id),
    CONSTRAINT api_token_application_scopes_token_fk
        FOREIGN KEY (workspace_id, token_id)
        REFERENCES open_aspm.api_tokens (workspace_id, id),
    CONSTRAINT api_token_application_scopes_application_fk
        FOREIGN KEY (workspace_id, application_id)
        REFERENCES open_aspm.applications (workspace_id, id)
);

CREATE INDEX role_bindings_authorization_idx
    ON open_aspm.role_bindings (
        workspace_id, principal_id, scope_type, application_id, valid_from, valid_until
    );

CREATE INDEX api_tokens_principal_idx
    ON open_aspm.api_tokens (workspace_id, principal_id, id);
