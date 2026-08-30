#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-access-control-postgres-plugin\nlenso-capability-access-control\nlenso-capability-access-control-admin\nlenso-capability-access-control-directory'
actual_crates="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -print0 | xargs -0 sed -n 's/^name = "\([^"]*\)"/\1/p' | sort)"

if [[ "$actual_crates" != "$expected_crates" ]]; then
  echo "unexpected workspace crate boundary" >&2
  diff -u <(printf '%s\n' "$expected_crates") <(printf '%s\n' "$actual_crates") || true
  exit 1
fi

expected_external_path=''
actual_external_paths="$(rg --no-heading --with-filename -o 'path\s*=\s*"\.\./\.\./[^"]+"' --glob 'Cargo.toml' . || true)"
if [[ "$actual_external_paths" != "$expected_external_path" ]]; then
  echo "unexpected cross-repository integration path" >&2
  exit 1
fi

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
metadata="$($cargo_bin metadata --locked --format-version=1)"
for package in lenso lenso-app-plan lenso-kernel lenso-native-adapter lenso-plugin-authoring lenso-contract-runtime lenso-postgres-kit; do
  count="$(jq --arg package "$package" '[.packages[] | select(.name == $package)] | length' <<<"$metadata")"
  if [[ "$count" != "1" ]]; then
    echo "$package resolved $count times; exactly one suite source is required" >&2
    exit 1
  fi
done

if rg -n 'lenso-platform-|lenso-module-|HostBuilder|HostLinkedModule|ModuleManifest' \
  Cargo.toml crates README.md CONTEXT.md --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found" >&2
  exit 1
fi
