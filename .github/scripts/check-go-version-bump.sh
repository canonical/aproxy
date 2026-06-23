#!/usr/bin/env bash
set -euo pipefail

BASE_SHA="${1:-}"
HEAD_SHA="${2:-}"

if [[ -z "$BASE_SHA" || -z "$HEAD_SHA" ]]; then
  echo "Usage: $0 <base-sha> <head-sha>"
  exit 1
fi

git fetch --no-tags --depth=1 origin "$BASE_SHA" "$HEAD_SHA"

GO_CHANGED="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" -- '**/*.go' 'go.mod' 'go.sum' || true)"
if [[ -z "$GO_CHANGED" ]]; then
  echo "No Go files or dependencies changed; skipping version bump check."
  exit 0
fi

BASE_VERSION="$(git show "$BASE_SHA:aproxy.go" | sed -n 's/^var version = "\([^"]*\)"$/\1/p' | head -n1)"
CURRENT_VERSION="$(sed -n 's/^var version = "\([^"]*\)"$/\1/p' aproxy.go | head -n1)"

if [[ -z "$BASE_VERSION" ]]; then
  echo "Could not parse base version from aproxy.go at $BASE_SHA"
  exit 1
fi

if [[ -z "$CURRENT_VERSION" ]]; then
  echo "Could not parse current version from aproxy.go"
  exit 1
fi

LATEST="$(printf '%s\n%s\n' "$BASE_VERSION" "$CURRENT_VERSION" | sort -V | tail -n1)"
if [[ "$CURRENT_VERSION" == "$BASE_VERSION" || "$LATEST" != "$CURRENT_VERSION" ]]; then
  echo "Go files changed but version was not bumped."
  echo "Base version:    $BASE_VERSION"
  echo "Current version: $CURRENT_VERSION"
  echo "Please bump var version in aproxy.go when modifying Go source files."
  exit 1
fi

echo "Version bump check passed: $BASE_VERSION -> $CURRENT_VERSION"
