# Release process

The three Access Control Capability 0.2.0 packages are already registered and
remain immutable. The changed release cohort is limited to:

- `lenso-access-control-core` 0.1.1
- `lenso-access-control-postgres-plugin` 0.2.2
- `lenso-access-control-d1-plugin` 0.1.1

Agent Tools and Workers smoke packages have `publish = false` and are outside
this release set. Do not change their publication policy as part of an
implementation release.

## Manual qualification and publication

`.github/workflows/release-plz.yml` has only `workflow_dispatch`. A Main push
cannot publish packages or create a release PR. The default `dry-run` job has
read permissions; it cannot obtain an OIDC publishing token.

Dispatch from Main with the full `source_sha`, exact `candidate_run_id` and
`candidate_attempt`, and a JSON `release_set` of `package_name`/`version`
objects. The set must equal the current registry-derived pending subset of
the three versions above. Extra packages, wrong versions, duplicate names and
unknown registry responses fail closed.

The gate verifies the checkout against a fresh remote Main readback. It
requires the matching `candidate/**` push CI workflow, SHA and attempt, with
one successful `quality` job and one successful `workers` job. An older
attempt, a different branch or missing job cannot qualify the source.

Normalized Cargo package verification runs only for the pending changed
packages. It consumes the registered Capability archives without repacking
their published versions. Archive inspection checks name, version, clean VCS
SHA and both Cargo manifests, and records archive SHA256 digests.

Live mode requires separate human authorization and `confirmation=publish`.
The live job repeats the source, candidate, pending-set and archive checks
immediately before pinned release-plz, using only `.github/release-workers.toml`.
It reconciles the action's exact package records, Primary version visibility,
source-bound Git tags and GitHub releases, including after partial failure.
A failed or unknown publication is inspected before any further dispatch.
Landing this workflow does not authorize a live dispatch.

Trusted Publisher coordinates for these registered package names are:

- repository owner: `LioRael`
- repository name: `lenso-access-control-plugin`
- workflow filename: `release-plz.yml`
- environment: unset

Confirm these coordinates in each crate's settings before authorized live
publication. Current [crates.io documentation](https://crates.io/docs/trusted-publishing)
requires a name's first publication before its Trusted Publisher can be
configured. All three names in this cohort already exist; no first-name
bootstrap is included here. Publication order is Core, then PostgreSQL and D1.
The workflow does not change publisher settings or allocate crate names.

## SDK35 source upgrade

The SDK35 source cohort selects Kernel 0.3.12, facade 0.5.28, Native Adapter
0.3.19 and Codegen 0.10.1. The three registered Capability 0.2.0 archives
retain their original package versions and compatible primary Kernel 0.3.5
minimum. Their contract source, schemas and generated Rust are byte-identical
to the immutable registry archives. Consumer locks select the current Kernel;
this does not require republishing unchanged Capability packages.

The required package checks select the changed public Core 0.1.1, PostgreSQL
0.2.2 and D1 0.1.1 cohort. Cargo's normalized verification consumes the
registered Capability archives instead of repacking their same published
versions into a local registry. Both Native and Wasm package verification
remain required. The new facility implementation also requires the coordinated
SDK35 producer packages to be available in the registry. A passing source
check with Git patches is not a passing registry archive check. Registry
publication requires separate authorization and is not performed by this
source upgrade.
