# Contributing

Access Control is an independent Lenso Plugin. Contributions must preserve
default deny, scoped allow-only RBAC, protected bootstrap, audienced mutation,
and monotonic policy revisions. Keep PostgreSQL private and do not add D1
changes to a PostgreSQL or release-only change.

## Ways to contribute

Use any editor and either a local clone or an optional Delta checkout. Delta
Land is an optional managed delivery path, not a required account or shell
permission. The `/land` command is a Delta action and is not a universal
command.

Fork the repository, make a focused branch, and open an Issue containing the
immutable commit SHA, the checks you ran, and known limitations. A maintainer
reviews or imports that exact revision, runs the final candidate CI, and
fast-forwards the same verified SHA to `main`. Do not ask reviewers to trust a
moving branch.

## Before handoff

Read `AGENTS.md` and the relevant package documentation. Run the narrowest
meaningful checks for the files changed:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
```

PostgreSQL acceptance and Workers checks require their documented disposable
services and toolchains. Explain unavailable services or skipped checks rather
than claiming they passed. Workflow and documentation changes should also run
YAML, Markdown/link, and shell/configuration checks available in the checkout.
The maintainer's candidate `quality` job is the authoritative native and
WASM proof.

For an offline or durable handoff, attach a format patch made from the exact
commit (`git format-patch --stdout <base>..HEAD > access-control.patch`) and
the SHA separately. Maintainers should inspect the patch before importing it.
Treat workflow files, scripts, and generated/configuration changes as untrusted:
review commands, pinned actions, permissions, and dependency boundaries before
running them.

## Review and delivery

Maintainers import or review the immutable SHA, absorb fixes, and push one
candidate ref under `delta/verify/**`. Candidate CI must pass the required
`quality` and `workers` jobs for that exact SHA and run attempt. Only then is
the exact candidate SHA fast-forwarded normally to `main`; no force-push,
release tag, package publication, or deployment is part of contribution
delivery.

Delta users may use the repository Land skill for the same sequence. Other
agents and plain Git users should follow these steps manually; `/land` is not
available as a universal shell command and does not grant GitHub permissions.
