#!/usr/bin/env bash

set -e

docker run \
  --rm -e CGO_ENABLED=1 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v `pwd`:/go/src/datadog-sbom-generator \
  -w /go/src/datadog-sbom-generator ghcr.io/goreleaser/goreleaser-cross \
  --clean --skip=validate --skip=publish --snapshot
