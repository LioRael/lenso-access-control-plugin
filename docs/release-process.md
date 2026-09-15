# Release process

The Capability, core, PostgreSQL, D1, and Agent Tools crates are public.
`lenso-access-control-workers-smoke` is private and must not be published. Initial publication is performed
in dependency order; later releases use `.github/workflows/release-plz.yml`
through crates.io Trusted Publishing.

Trusted Publisher coordinates for every crate in this repository are:

- repository owner: `LioRael`
- repository name: `lenso-access-control-plugin`
- workflow filename: `release-plz.yml`
- environment: unset

The live workflow is manual and requires both `live=true` and
`confirm=publish` from the `main` branch. Pushes to `main` may create a release
PR, but never publish crates directly.

Confirmed manual dispatch publishes every unpublished version on `main`, including
versions prepared in a compatibility PR. It does not require the current commit
to have been authored by release-plz. The dry-run uses the same selection policy;
`release_always` does not bypass the workflow ref, confirmation or OIDC gates.


Publish shared Capabilities before `lenso-access-control-core`, then publish the
backend Plugins that depend on it. The new core and D1 crates require their own
crates.io Trusted Publisher setup before their first release. Local qualification
does not claim these new packages are already available in the registry.


For the Workers cohort, dispatch with `scope=workers` for both dry-run and live.
The checked-in `.github/release-workers.toml` selects only Core 0.1.0, D1 0.1.0,
and PostgreSQL 0.2.1. It does not publish the unrelated, previously unpublished
Agent Tools package. The default `scope=all` retains the repository-wide release
behavior. Verify registry visibility and run the Workers consumer against the
released dependency graph before marking this cohort delivered.
