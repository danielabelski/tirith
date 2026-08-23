#!/usr/bin/env bash
# Assemble npm packages from producer-isolated release artifacts.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <artifact-root>" >&2
  exit 2
fi

version="${1#v}"
artifact_root="$2"

package_archives=(
  "darwin-arm64:tirith-aarch64-apple-darwin/tirith-aarch64-apple-darwin.tar.gz:tirith"
  "darwin-x64:tirith-x86_64-apple-darwin/tirith-x86_64-apple-darwin.tar.gz:tirith"
  "linux-x64:tirith-x86_64-unknown-linux-gnu/tirith-x86_64-unknown-linux-gnu.tar.gz:tirith"
  "linux-arm64:tirith-aarch64-unknown-linux-gnu/tirith-aarch64-unknown-linux-gnu.tar.gz:tirith"
  "win32-x64:tirith-x86_64-pc-windows-msvc/tirith-x86_64-pc-windows-msvc.zip:tirith.exe"
)

for package_archive in "${package_archives[@]}"; do
  IFS=':' read -r platform archive binary <<< "$package_archive"
  source_archive="${artifact_root}/${archive}"
  package_dir="npm/${platform}"
  if [[ ! -f "$source_archive" ]]; then
    echo "ERROR: missing npm source artifact from its named producer: $source_archive" >&2
    exit 1
  fi

  extract_dir=$(mktemp -d)
  if [[ "$archive" == *.zip ]]; then
    unzip -q "$source_archive" -d "$extract_dir"
  else
    tar xzf "$source_archive" -C "$extract_dir"
  fi
  if [[ ! -f "${extract_dir}/${binary}" ]]; then
    echo "ERROR: source artifact $source_archive does not contain $binary" >&2
    rm -rf -- "$extract_dir"
    exit 1
  fi
  mkdir -p "${package_dir}/bin"
  cp "${extract_dir}/${binary}" "${package_dir}/bin/${binary}"
  chmod +x "${package_dir}/bin/${binary}" 2>/dev/null || true
  rm -rf -- "$extract_dir"

  VERSION="$version" PACKAGE_JSON="${package_dir}/package.json" node <<'NODE'
const fs = require('fs');
const path = process.env.PACKAGE_JSON;
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
pkg.version = process.env.VERSION;
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
NODE
done

VERSION="$version" node <<'NODE'
const fs = require('fs');
const path = 'npm/tirith/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
pkg.version = process.env.VERSION;
for (const dependency of Object.keys(pkg.optionalDependencies || {})) {
  pkg.optionalDependencies[dependency] = process.env.VERSION;
}
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
NODE
chmod +x npm/tirith/bin/tirith
