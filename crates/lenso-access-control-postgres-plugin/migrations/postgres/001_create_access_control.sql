CREATE TABLE access_control_scopes (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    bootstrap_subject TEXT NOT NULL,
    policy_revision BIGINT NOT NULL DEFAULT 0 CHECK (policy_revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_kind, scope_id)
);

CREATE TABLE access_control_roles (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_kind, scope_id, role_id),
    FOREIGN KEY (scope_kind, scope_id)
        REFERENCES access_control_scopes(scope_kind, scope_id)
        ON DELETE CASCADE
);

CREATE TABLE access_control_role_permissions (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (scope_kind, scope_id, role_id, permission),
    FOREIGN KEY (scope_kind, scope_id, role_id)
        REFERENCES access_control_roles(scope_kind, scope_id, role_id)
        ON DELETE CASCADE
);

CREATE TABLE access_control_subject_roles (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_kind, scope_id, subject, role_id),
    FOREIGN KEY (scope_kind, scope_id, role_id)
        REFERENCES access_control_roles(scope_kind, scope_id, role_id)
        ON DELETE CASCADE
);

CREATE INDEX access_control_subject_roles_lookup
    ON access_control_subject_roles(scope_kind, scope_id, subject);

CREATE INDEX access_control_role_permissions_lookup
    ON access_control_role_permissions(scope_kind, scope_id, permission, role_id);
