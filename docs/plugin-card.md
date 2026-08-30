# Access Control v1 Plugin card

## Owner and deletion boundary

The PostgreSQL Plugin owns scoped role definitions, role permission grants,
subject-role bindings, the protected bootstrap role, and monotonic policy
revisions. Removing its package, Instance, bindings, and schema removes RBAC
without removing Organizations, memberships, projects, documents, or other
scope-owner facts.

## Capabilities

- Provides `lenso.access-control@1` with `check_permission`.
- Provides `lenso.access-control-admin@1` with `bootstrap_scope`,
  `create_role`, `set_role_permissions`, `delete_role`, `assign_role`, and
  `revoke_role`.
- Provides `lenso.access-control-directory@1` with `get_role`, `list_roles`,
  and `list_subject_roles` for exact configured peer Plugin callers. Results
  include the current policy revision and sorted permission snapshots.
- Requires exactly one `lenso.secrets@1` Provider for the PostgreSQL URL.

The access check is portable and default-deny. Administration is transport
authorized by its resolved binding, bootstrap authorized by exact configured
caller Instance, and post-bootstrap authorized by a verified Auth assertion
plus current scoped RBAC state.

## State and lifecycle

Configuration supplies an owned schema, a database URL secret reference, Auth
issuer/public verification key, exact bootstrap caller Instance keys, and a
separate allowlist for read-only Directory consumers.
Activation resolves the secret and verifies an already-installed schema.
Deactivation closes the pool. Setup and upgrade remain explicit operator work.

## Honest limits

Access Control does not verify scope existence or membership. Organization
migration is separate. Audit delivery is not present because there is not yet
a vNext Audit Capability. Role inheritance, explicit deny, direct grants,
conditional policy, relationship traversal, and a Console surface are outside
v1.
