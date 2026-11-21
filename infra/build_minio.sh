#!/usr/bin/env bash
# Build MinIO from its official source and package it as the local image
# rbpre-minio:<tag>. MinIO no longer publishes official container images, so
# the release used by the experiments is built from github.com/minio/minio at a
# pinned tag. Go downloads the toolchain the release requires (GOTOOLCHAIN=auto).
#
#   MINIO_TAG  release tag   (default RELEASE.2025-10-15T17-29-55Z)
#   MINIO_SRC  source tree   (default ~/src/minio; cloned if missing)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
TAG="${MINIO_TAG:-RELEASE.2025-10-15T17-29-55Z}"
SRC="${MINIO_SRC:-$HOME/src/minio}"
export PATH="/usr/local/go/bin:$PATH" GOTOOLCHAIN=auto CGO_ENABLED=0
export MINIO_RELEASE=RELEASE  # version string RELEASE.<date> instead of DEVELOPMENT.<date>

[ -d "$SRC" ] || git clone -q --depth 1 --branch "$TAG" https://github.com/minio/minio.git "$SRC"
cd "$SRC"
[ "$(git describe --tags --exact-match HEAD 2>/dev/null)" = "$TAG" ] || { echo "$SRC is not at $TAG" >&2; exit 1; }

ldflags="$(go run buildscripts/gen-ldflags.go)"
go build -tags kqueue -trimpath -ldflags "$ldflags" -o "$here/minio/minio" .
"$here/minio/minio" --version | head -1
docker build -q -t "rbpre-minio:$TAG" "$here/minio"
