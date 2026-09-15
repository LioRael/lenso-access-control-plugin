CREATE TABLE access_control_scopes (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    bootstrap_subject TEXT NOT NULL,
    policy_revision INTEGER NOT NULL DEFAULT 0 CHECK (typeof(policy_revision) = 'integer' AND policy_revision >= 0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (scope_kind, scope_id)
);

CREATE TABLE access_control_roles (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    name TEXT NOT NULL,
    protected INTEGER NOT NULL DEFAULT FALSE CHECK(protected IN (0,1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
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
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (scope_kind, scope_id, subject, role_id),
    FOREIGN KEY (scope_kind, scope_id, role_id)
        REFERENCES access_control_roles(scope_kind, scope_id, role_id)
        ON DELETE CASCADE
);

CREATE INDEX access_control_subject_roles_lookup
    ON access_control_subject_roles(scope_kind, scope_id, subject);

CREATE INDEX access_control_role_permissions_lookup
    ON access_control_role_permissions(scope_kind, scope_id, permission, role_id);

-- Transaction-local workspace. Every operation clears it before committing.
-- A fixed key is safe because D1 serializes atomic write batches.
CREATE TABLE access_control_operation (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    actor TEXT,
    subject TEXT,
    role_id TEXT,
    name TEXT,
    permissions TEXT,
    failure TEXT,
    changed INTEGER NOT NULL DEFAULT 0 CHECK(changed IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 0
);
