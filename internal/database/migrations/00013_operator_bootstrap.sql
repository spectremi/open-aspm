-- +goose Up
CREATE TABLE open_aspm.bootstrap_installations (
    id varchar(32) PRIMARY KEY,
    workspace_id varchar(128) NOT NULL,
    application_id varchar(128) NOT NULL,
    principal_id varchar(128) NOT NULL,
    role_id varchar(128) NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT bootstrap_installations_singleton CHECK (id = 'initial'),
    CONSTRAINT bootstrap_installations_workspace_unique UNIQUE (workspace_id),
    CONSTRAINT bootstrap_installations_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES open_aspm.workspaces (id),
    CONSTRAINT bootstrap_installations_application_fk
        FOREIGN KEY (workspace_id, application_id)
        REFERENCES open_aspm.applications (workspace_id, id),
    CONSTRAINT bootstrap_installations_principal_fk
        FOREIGN KEY (principal_id) REFERENCES open_aspm.principals (id),
    CONSTRAINT bootstrap_installations_role_fk
        FOREIGN KEY (workspace_id, role_id)
        REFERENCES open_aspm.roles (workspace_id, id)
);
