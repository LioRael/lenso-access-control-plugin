# Lenso Access Control Plugin

Independent allow-only RBAC for Lenso applications.

This repository provides:

- `lenso.access-control@1` for default-deny scoped permission checks;
- `lenso.access-control-admin@1` for bootstrap, role, grant, and binding
  administration; and
- `lenso.access-control-directory@1` for read-only role and subject-binding
  projections admitted to exact peer Plugin Instance keys; and
- `lenso-access-control-postgres-plugin`, which owns one operator-managed
  PostgreSQL schema.

Access Control addresses scopes only through stable opaque `{ kind, id }`
references. Scope-owning Plugins remain authoritative for scope existence,
membership eligibility, ownership, archival, and every resource-local rule.
An RBAC allow is therefore necessary only when a target workflow declares it;
it is never sufficient final authorization.

## First slice

- Missing bindings deny by default.
- A subject's permissions are the union of every role bound in one scope.
- Direct subject grants, explicit deny, role inheritance, conditions, and
  relationship traversal are absent.
- Bootstrap creates one protected `access-control.bootstrap-admin` role with
  `access-control.roles.manage` and `access-control.bindings.manage`.
- Bootstrap callers are exact App-local Plugin Instance keys.
- All later mutations require an operation-audienced, cryptographically valid
  Auth `ActorAssertion` and the corresponding scoped administration grant.
- Every effective mutation advances a monotonic per-scope policy revision in
  the same transaction.
- Directory reads return role names, grants, protected state, and the policy
  revision from one PostgreSQL snapshot. Role and subject-role lists use
  stable role-ID keyset pagination and never expose the private tables.

Directory access does not itself prove Organization membership or authority to
approve a role. Callers such as Access Request must combine the immutable role
snapshot with Organization Membership, their own workflow, and final
resource-local authorization. Directory caller admission is intentionally
separate from bootstrap authority and post-bootstrap human administration.

## Operator setup

```rust,no_run
use lenso_access_control_postgres_plugin::AccessControlOperator;

# async fn setup(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
AccessControlOperator::setup(database_url, "access_control").await?;
# Ok(())
# }
```

App boot resolves only the configured database URL reference through the bound
Secrets Provider and verifies that the exact schema is already installed.

## Focused verification

```sh
lenso-contract-codegen check \
  crates/lenso-capability-access-control/capability.json \
  --rust crates/lenso-capability-access-control/src/generated.rs
lenso-contract-codegen check \
  crates/lenso-capability-access-control-admin/capability.json \
  --rust crates/lenso-capability-access-control-admin/src/generated.rs
lenso-contract-codegen check \
  crates/lenso-capability-access-control-directory/capability.json \
  --rust crates/lenso-capability-access-control-directory/src/generated.rs
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo \
  check --locked --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo \
  test --locked --workspace
```

Optional PostgreSQL acceptance requires a disposable database whose name
starts with `lenso_access_control_test`:

```sh
LENSO_ACCESS_CONTROL_TEST_DATABASE_URL=postgres://... \
  /Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo \
  test --locked -p lenso-access-control-postgres-plugin \
  --features postgres-acceptance
```

## Releases

The Capability crates and PostgreSQL implementation are published separately
so Access Control remains an independent, replaceable Plugin rather than an
Organization-internal policy table. Future releases use crates.io Trusted
Publishing; see [`docs/release-process.md`](docs/release-process.md).
