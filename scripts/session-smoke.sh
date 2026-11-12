#!/usr/bin/env bash
set -euo pipefail

# Linux operator-side fixture; socat/curl/jq are test tools, not runtime brokers.
wrapper="${SYDGUARD_TEST_WRAPPER:-bin/sydguard}"
engine="${SYDGUARD_TEST_SYD:-$HOME/.local/opt/syd-3.59.0-static/bin/syd}"
command -v jq >/dev/null
command -v curl >/dev/null
output=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$output"
}
trap cleanup EXIT
name="session-smoke-$$"
for i in 1 2 3; do
  "$wrapper" run --backend native --name "$name" --syd "$engine" -- /bin/sleep 3 >"$output/$i.log" 2>&1 &
  pids+=("$!")
done
found=false
for _ in {1..30}; do
  if "$wrapper" sessions --backend native --json >"$output/active.json"; then
    count=$(jq --arg prefix "$name" '[.[] | select(.name | startswith($prefix))] | length' "$output/active.json")
    if [[ "$count" == 3 ]]; then found=true; break; fi
  fi
  sleep 0.05
done
[[ "$found" == true ]] || { printf 'Expected three simultaneous registered sessions\n' >&2; exit 1; }
jq -e --arg name "$name" '[.[] | select(.name | startswith($name)) | .name] | sort == ([$name, ($name+"-1"), ($name+"-2")] | sort)' "$output/active.json" >/dev/null
for pid in "${pids[@]}"; do wait "$pid"; done
pids=()
"$wrapper" sessions --backend native --history --json >"$output/history.json"
jq -e --arg prefix "$name" '[.[] | select(.name | startswith($prefix)) | select(.state == "exited")] | length == 3' "$output/history.json" >/dev/null

config_path=$("$wrapper" config path)
state="$(dirname "$config_path")/state"
# shellcheck disable=SC2016 # $1 is intentionally expanded only by the confined child.
"$wrapper" run --backend native --syd "$engine" -- /bin/sh -c '
set -eu
if cat "$1/operator.token"; then echo AUTHORITY_READ_BYPASS; exit 91; fi
if curl --max-time 2 --unix-socket "$1/controller.sock" http://sydguard/api/health; then echo CONTROLLER_SOCKET_BYPASS; exit 92; fi
printf "CONTROLLER_BOUNDARY_PASS\n"
' fixture "$state"
printf 'NAMED_SESSION_SMOKE_PASS\n'
