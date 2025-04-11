#!/usr/bin/env bash

set -ex

go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run ./... --max-same-issues 0 --timeout 60m
