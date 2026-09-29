# Management scope authorization

Access Control retains opaque `{kind,id}` scopes, allow-only role union and
current policy revisions. The scope owner verifies application/deployment
existence, membership and resource rules. Management intersects the current
RBAC decision with credential/delegation ceilings; neither membership nor an
approval overrides a denial. This repository does not add a Console-specific
role engine, wildcard tree or second membership truth.

Management mutations now require a verified `user` actor. A valid machine
assertion cannot act as a person even when its subject string matches a role
binding. Bootstrap and directory caller configuration accepts an exact normal
Plugin Root `plugin-id/instance-key` as well as legacy local keys; extra path
segments, empty segments and aliases remain rejected. Bootstrap stays outside
Agent tools. Production Management composition excludes the legacy Agent admin
adapter unless it goes through the complete shared Management policy.

The policy state is read at each operation, and effective mutation plus revision
remain one backend transaction. The native PostgreSQL and existing SQLite-backed
D1 conformance fixtures are validated with the latest Lenso and generated DX.
SQLite fixtures do not qualify deployed D1/workerd or PG/Hyperdrive. Target
business commits still belong to the target and are not atomically coupled to a
policy database read.

## Verification

```sh
lenso-contract-codegen workspace check --manifest-path Cargo.toml
LENSO_ACCESS_CONTROL_TEST_DATABASE_URL=postgresql://.../lenso_access_control_test_security \
  cargo test --locked --workspace --features postgres-acceptance
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Existing backend tests preserve default deny, same-scope union, cross-scope
isolation, protected bootstrap and monotonic revisions. Candidate CI admits
`candidate/**` in addition to the existing managed delivery ref namespace.
