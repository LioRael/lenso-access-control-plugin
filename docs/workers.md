# Access Control on Workers/D1

## Ownership and selection

`lenso.access-control.d1` provides the existing Access Control, Administration,
and Directory Capabilities. It owns only scoped RBAC policy. Scope existence,
membership eligibility, and final resource authorization stay with the consuming
Plugin. Removing the provider, its bindings, and owned database removes RBAC.

The existing `lenso.access-control.postgres` Plugin retains its PostgreSQL
configuration and Secrets requirement. D1 has a separate identity because its
configuration and resource requirements differ. Both delegate request validation,
Auth assertion projection, caller admission, error mapping, and response formatting
to `lenso-access-control-core`. That library is an implementation dependency, not
a separately activated Plugin or Capability.

D1 configuration contains `binding`, `auth_issuer`, `auth_assertion_public_key`,
`bootstrap_callers`, and optional `directory_callers`. The public verification key
is not a secret. D1 needs no database URL or Secrets requirement. Its linked
factory alone cannot activate a usable Instance: the Host must explicitly inject
the named binding. A missing or mismatched binding fails startup.

## Event-owned Host integration

Use the released `@lenso/workers-runtime` HTTP Host and create a fresh scope,
registry, and factory for every request. Pass the callback returned by
`workers/binding.mjs` into:

```rust,ignore
lenso_access_control_d1_plugin::workers::factory("ACCESS", batch_callback)
```

The callback uses the base D1 database binding directly. It uses the shared
scope's `run` resource boundary to reject closed-event work, track native I/O,
and detach late continuations when a Wasm generation is retired. Do not pass a
replica session or cache an event's callback/factory globally. The callback is a
private storage transport and never interprets business requests or authorizes
callers. JavaScript exceptions and malformed D1 receipts become sanitized Runtime
Failures. Submitted writes are never retried automatically: a transport failure
after submission can mean the transaction committed.

## Migration and lifecycle

Each backend stores SQL under its package's `migrations/<backend>/` directory.
PostgreSQL's v1 SQL bytes, migration name, and version are unchanged by the move.
PostgreSQL uses `lenso-postgres-kit 0.1.1`; D1 uses `lenso-migration` and
`lenso-migration-d1 0.1.0`.

An operator explicitly calls `schema::plan()?.setup(&binding).await` against a
fresh dedicated D1 database, or `upgrade` against an existing managed database.
Runtime activation calls only `verify`; it never installs or upgrades a schema.
Generated statement byte boundaries come from SQLite's author-time parser:

```sh
python3 scripts/generate-d1-migrations.py --check
```

The D1 operation workspace is empty between committed operations. It belongs to
Access Control, contains no cross-Plugin data, and is removed with the database.

## Transaction semantics

Every administration operation sends a single primary D1 atomic batch:

1. Acquire the serialized write transaction by clearing the operation workspace.
2. Capture the current revision, current actor permission, operation-specific
   domain failure, and whether the requested change is effective.
3. Apply writes only when admitted and effective; increment the revision once.
4. Return the captured result and clear the workspace before committing.

Authorization is evaluated before any writes and within the same transaction.
A concurrent administrator revocation either follows an authorized mutation or
precedes it and denies it. Denied and duplicate no-op requests never advance the
revision. A late SQL failure rolls back the entire batch, including its workspace.
The protected bootstrap role and its last binding follow the PostgreSQL rules.
A duplicate create remains `RoleAlreadyExists`; assignment and grant replacement
retain their existing idempotent semantics.

Directory responses read their revision, role page, and sorted permission lists
in one SQLite statement, returning one result row per role rather than one giant
JSON cell for the entire page. Both backends use bytewise role and permission order;
PostgreSQL explicitly uses the `C` collation so cursor semantics do not depend on
the database locale. This makes mixed-case ordering deterministic; consumers must
not assume locale-specific display sorting. Each page is a current snapshot;
pages requested at different times are not a single historical snapshot.

The shared authorization clock enables `time`'s Wasm binding support on wasm32,
so assertion validity uses the Workers wall clock rather than unsupported native
`SystemTime`. D1 returns revisions as decimal text, preserving values above JavaScript's exact
integer range. Revision overflow fails the transaction. Maximum grant replacement
uses one JSON parameter and `json_each`, retaining the 256-permission contract
without exceeding D1's parameter limit.

## Qualification

`lenso-access-control-core` has opt-in `conformance` vectors used by the actual
PostgreSQL, SQLite, and Wasm/D1 implementations. They exercise domain errors,
no-ops, protected policy, grant replacement, revocation, sorted snapshots, keyset
pages, and revision increments. SQLite tests also inject a late write failure,
verify boot performs no DDL, reject history drift, and cover large revisions.

`crates/lenso-access-control-workers-smoke` is a private qualification Host.
`workers/proof.mjs` runs its actual Wasm inside workerd with real local D1 bindings,
including Kernel startup, typed consumer calls with operation-audienced Auth
assertions, request closure, malformed bindings, provider removal, concurrent
events, and competing revocation/administration batches. Fixture keys are synthetic.

```sh
pnpm --dir workers install --frozen-lockfile
bash workers/build.sh
node workers/proof.mjs
```

These are local workerd proofs, not a Cloudflare deployment or production database
migration. Publication and downstream adoption are separate delivery steps.


The verified local receipt is [workers-proof.json](workers-proof.json).
The transaction and primary-binding requirements follow Cloudflare's
[D1 database API](https://developers.cloudflare.com/d1/worker-api/d1-database/).
