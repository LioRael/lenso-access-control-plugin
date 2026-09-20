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

The checked-in workflow is manual and read-only. Dispatch it from `main` with
the full landed `source_sha`, an exact JSON `release_set`, `candidate_run_id`,
and `candidate_attempt`, using `mode=dry-run`. It verifies that the SHA is the
current landed `main` commit and that the matching candidate `quality` run
passed before running pinned release-plz with `dry_run: true`. It cannot
publish, create tags, or create release PRs. This is the remaining release
boundary: an owner must separately authorize and implement a future publication
workflow while preserving the package allowlist, action pins, OIDC identities,
and dependency order below.

Publish shared Capabilities before `lenso-access-control-core`, then publish the
backend Plugins that depend on it. crates.io requires the first Core and D1 upload to use an existing API token;
Trusted Publishing can only be configured after the crate exists. Bootstrap
those exact versions from the merged commit using the normal Cargo credential
provider, then configure this repository/workflow as their Trusted Publisher.
Subsequent publications use the confirmed OIDC workflow. Local qualification
does not claim these new packages are already available in the registry.


For the Workers cohort, dispatch with `scope=workers` for both dry-run and live.
The checked-in `.github/release-workers.toml` selects only Core 0.1.0, D1 0.1.0,
and PostgreSQL 0.2.1. It does not publish the unrelated, previously unpublished
Agent Tools package. The default `scope=all` retains the repository-wide release
behavior. Verify registry visibility and run the Workers consumer against the
released dependency graph before marking this cohort delivered.
