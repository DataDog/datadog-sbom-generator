#!/usr/bin/env bash

set -e
env -u DD_API_KEY -u DD_APP_KEY go test ./... -coverpkg=./... -covermode=atomic -coverprofile coverage.out
