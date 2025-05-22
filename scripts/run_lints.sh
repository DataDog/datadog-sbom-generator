#!/usr/bin/env bash

FIX_FLAG=""
if [[ "$1" == "--fix" ]]; then
  FIX_FLAG="--fix"
fi

set -ex

go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run ./... --max-same-issues 0 --timeout 60m $FIX_FLAG

