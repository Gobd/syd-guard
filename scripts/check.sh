#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in go gofumpt golangci-lint shellcheck; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing required check tool: %s\n' "$tool" >&2
    exit 1
  fi
done

if [[ "${1:-}" == --fix ]]; then
  gofumpt -w cmd internal
elif [[ $# -gt 0 ]]; then
  printf 'Usage: scripts/check.sh [--fix]\n' >&2
  exit 2
fi

unformatted="$(gofumpt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
  printf 'Run scripts/check.sh --fix; unformatted Go:\n%s\n' "$unformatted" >&2
  exit 1
fi

# Go embeds the frontend bundle; build it before testing or compiling consumers.
if [[ -f web/package.json ]]; then
  command -v bun >/dev/null 2>&1 || { printf 'Missing Bun\n' >&2; exit 1; }
  (
    # Inspect the global command list outside any package directory; old Bun
    # releases can resolve unknown commands to package scripts recursively.
    help="$(cd / && bun --help)"
    for capability in lint fmt check; do
      if ! grep -Eq "^[[:space:]]+${capability}[[:space:]]" <<<"$help"; then
        printf 'This Bun binary lacks native %s; install a supported Bun build. No external-tool fallback.\n' "$capability" >&2
        exit 1
      fi
    done
    cd web
    bun install --frozen-lockfile
    if [[ "${1:-}" == --fix ]]; then
      bun run fmt
    fi
    bun run lint
    bun run fmt:check
    bun run check
    bun run build
    bun run test
  )
else
  printf 'Frontend checks skipped: web/package.json does not exist yet.\n'
fi
go vet ./...
go test -race ./...
go build ./...
golangci-lint run

while IFS= read -r -d '' script; do
  shellcheck "$script"
done < <(find scripts -type f -name '*.sh' -print0)

printf 'All existing-code checks passed. Runtime sandbox/integration gates are separate.\n'
