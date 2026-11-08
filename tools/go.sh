#!/usr/bin/env bash
# Run the Go toolchain from the golang:1.25 image against this module (no Go is needed on the host).
# Caches live inside the module folder (.gocache, .gomodcache; gitignored). Extra docker flags: GO_DOCKER_FLAGS.
#   tools/go.sh vet ./...   |   tools/go.sh test ./...   |   tools/go.sh mod tidy
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/.gocache" "$ROOT/.gomodcache"
# shellcheck disable=SC2086  # GO_DOCKER_FLAGS is a deliberate word-split list of extra flags
exec docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/src" -w /src \
  -e GOCACHE=/src/.gocache -e GOMODCACHE=/src/.gomodcache -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=0 \
  ${GO_DOCKER_FLAGS:-} golang:1.25 go "$@"
