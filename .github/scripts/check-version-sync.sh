#!/usr/bin/env bash
set -euo pipefail

SNAP_VERSION="$(sed -n 's/^version:[[:space:]]*\(.*\)$/\1/p' snap/snapcraft.yaml | head -n1 | tr -d '"' | xargs)"
GO_VERSION="$(sed -n 's/^var version = "\([^"]*\)"$/\1/p' aproxy.go | head -n1)"

if [[ -z "$SNAP_VERSION" ]]; then
  echo "Could not parse version from snap/snapcraft.yaml"
  exit 1
fi

if [[ -z "$GO_VERSION" ]]; then
  echo "Could not parse version from aproxy.go"
  exit 1
fi

if [[ "$SNAP_VERSION" != "$GO_VERSION" ]]; then
  echo "Version mismatch detected"
  echo "snap/snapcraft.yaml version: $SNAP_VERSION"
  echo "aproxy.go version:         $GO_VERSION"
  echo "Keep both versions synchronized before merging or releasing."
  exit 1
fi

echo "Version check passed: $GO_VERSION"
