# Lenso Access Control context

`lenso-access-control-plugin` owns independent, scoped, allow-only RBAC for
Lenso vNext. It does not own Organizations, membership, scope existence,
authentication, or resource-local authorization.

`lenso.access-control@1` answers one RBAC factor: whether a subject has a named
permission in an opaque `{ kind, id }` scope. Missing scope policy, role,
binding, or grant returns `allowed = false`. Multiple bound roles contribute
the union of their grants.

`lenso.access-control-admin@1` owns bootstrap, role, grant, and binding
mutations. Bootstrap is an idempotent transition admitted only from an exact
configured caller Instance. Later mutations verify the Auth `ActorAssertion`
carried by the invocation context for the exact administrative Operation, then
check the actor's scoped administration permission inside the same PostgreSQL
transaction as the mutation.

`lenso.access-control-directory@1` projects current role definitions and
subject-role bindings to exact configured peer Plugin Instance callers. Each
response carries the scope policy revision; paginated reads use the role ID as
a stable keyset boundary and execute in a repeatable-read snapshot. Directory
admission is not an RBAC allow and does not transfer final authorization to
Access Control.

Every effective mutation increments that scope's policy revision once. The
bootstrap administrator role cannot be deleted or have its grants replaced,
and its final subject binding cannot be revoked.
