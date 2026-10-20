#!/usr/bin/env bash
# Installs pinned scanner binaries into $1 (default: $RUNNER_TEMP/bin) and
# verifies each download against a checksum recorded here, so a compromised
# release asset or a moved tag cannot change what CI runs.
#
# Bump a version: update VERSION and SHA256 together, from the release's
# published checksums file, in a PR of its own.
set -euo pipefail

dest="${1:-${RUNNER_TEMP:-/tmp}/bin}"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

OSV_VERSION="v2.6.0"
OSV_SHA256="ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108" # osv-scanner_linux_amd64

GITLEAKS_VERSION="8.30.0"
GITLEAKS_SHA256="79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e" # gitleaks_8.30.0_linux_x64.tar.gz

fetch() { curl --fail --silent --show-error --location --retry 3 -o "$2" "$1"; }
verify() { echo "$1  $2" | sha256sum --check --strict --quiet; }

for tool in "${@:2}"; do
  case "$tool" in
    osv-scanner)
      fetch "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_amd64" "$tmp/osv-scanner"
      verify "$OSV_SHA256" "$tmp/osv-scanner"
      install -m 0755 "$tmp/osv-scanner" "$dest/osv-scanner"
      ;;
    gitleaks)
      fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "$tmp/gitleaks.tgz"
      verify "$GITLEAKS_SHA256" "$tmp/gitleaks.tgz"
      tar -xzf "$tmp/gitleaks.tgz" -C "$tmp" gitleaks
      install -m 0755 "$tmp/gitleaks" "$dest/gitleaks"
      ;;
    *)
      echo "unknown tool: $tool" >&2
      exit 1
      ;;
  esac
done

echo "$dest" >> "${GITHUB_PATH:-/dev/null}"
