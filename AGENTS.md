# Agent instructions

This repository owns independent, allow-only RBAC for Lenso vNext.

- Access Control owns scoped roles, permission grants, subject-role bindings,
  policy revisions, and RBAC decisions. Scope owners retain scope existence,
  membership eligibility, and final resource authorization.
- Keep PostgreSQL private. App boot verifies an operator-managed schema and
  never creates or migrates it.
- Bootstrap is restricted to exact configured caller Instance keys. Every
  post-bootstrap mutation requires a valid, operation-audienced Auth
  `ActorAssertion` and a scoped administration permission.
- Preserve default deny, allow-only multi-role union, the protected bootstrap
  role, and one monotonic revision increment per effective mutation.
- Capability descriptors and Schemas are authoritative. Regenerate Rust
  projections with `lenso-contract-codegen`; never hand-edit them.
- Run Cargo through
  `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`.
