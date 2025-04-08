#!/usr/bin/env bash

set -e

go test ./... -coverpkg=./... -covermode=atomic -coverprofile coverage.out
