#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux ]]; then
  printf 'Run runtime integration tests inside Linux/Lima/WSL.\n' >&2
  exit 1
fi
engine="${SYDGUARD_TEST_SYD:-$HOME/.local/opt/syd-3.59.0-static/bin/syd}"
if [[ ! -x "$engine" ]]; then
  printf 'Missing tested candidate: %s\nRun the upstream install script or set SYDGUARD_TEST_SYD explicitly.\n' "$engine" >&2
  exit 1
fi
export SYDGUARD_TEST_SYD="$engine"
go test -count=1 -v ./internal/syd -run Integration
