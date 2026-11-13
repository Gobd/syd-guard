#!/usr/bin/env bash
# All static checks. CI runs this; locally `scripts/check.sh --fix` formats first.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in go gofumpt golangci-lint shellcheck bun; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done
fix=0
case "${1:-}" in
  --fix) fix=1 ;;
  "") ;;
  *) echo "usage: scripts/check.sh [--fix]" >&2; exit 2 ;;
esac

# UI: Bun does lint/fmt/typecheck/test/build natively (no other JS tooling).
(
  cd web
  bun install --frozen-lockfile >/dev/null
  if [ "$fix" = 1 ]; then bun run fmt; fi
  bun run lint
  bun run fmt:check
  bun run check
  bun run test
  bun run build
)
# The built UI is committed (Go embeds it); it must match the sources.
if ! git diff --quiet -- internal/ui/dist || [ -n "$(git ls-files --others --exclude-standard internal/ui/dist)" ]; then
  echo "internal/ui/dist is stale: commit the rebuilt UI" >&2
  [ "$fix" = 1 ] || exit 1
fi

# Go
if [ "$fix" = 1 ]; then gofumpt -w cmd internal; fi
unformatted="$(gofumpt -l cmd internal)"
if [ -n "$unformatted" ]; then echo "gofumpt needed (scripts/check.sh --fix):" >&2; echo "$unformatted" >&2; exit 1; fi
go vet ./...
go test -race ./...
golangci-lint run
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/sydguard
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/sydguard
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./cmd/sydguard

# Shell
find scripts internal -name '*.sh' -print0 | xargs -0 shellcheck
echo "all checks passed (runtime tests: scripts/e2e.sh inside the VM)"
