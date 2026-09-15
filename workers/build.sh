#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
node "$root/node_modules/@lenso/workers-runtime/build.mjs" --manifest "$root/../Cargo.toml" --package lenso-access-control-workers-smoke --out-dir "$root/pkg"
