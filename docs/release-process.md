# Release process

All four workspace crates are public crates. Initial publication is performed
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
