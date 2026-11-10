#!/usr/bin/env bash
set -euo pipefail

echo "=== Building server for Linux AMD64 ==="

export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$PROJECT_ROOT/app/src/main/assets/linux-server"

go build -ldflags="-s -w" -o "$PROJECT_ROOT/app/src/main/assets/server" .

echo "OK: server built in app/src/main/assets"
