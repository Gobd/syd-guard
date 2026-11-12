#!/usr/bin/env bash
# Ordinary-UID opt-in fixture; a separately authorized administrator must inject
# the crash for crash mode after inspecting the disposable helper identity.
set -euo pipefail
: "${SYDGUARD_MANAGED_SMOKE:?set to 1 only after disposable reviewed setup}"
[[ "$SYDGUARD_MANAGED_SMOKE" == 1 ]] || { echo 'explicit opt-in required' >&2; exit 2; }
: "${SYDGUARD_BIN:?absolute candidate CLI path required}"
: "${SYDGUARD_FIXTURE_PROJECT:?absolute disposable registered project required}"
: "${SYDGUARD_PROJECT_ID:?registered project ID required}"
: "${SYDGUARD_PROFILE_REVISION:?reviewed exact revision required}"
mode="${SYDGUARD_LIFECYCLE_CASE:-detached}"
profile="${SYDGUARD_PROFILE_NAME:-default}"
[[ "$SYDGUARD_BIN" == /* && "$SYDGUARD_FIXTURE_PROJECT" == /* ]] || { echo 'absolute paths required' >&2; exit 2; }
[[ "$mode" == detached || "$mode" == crash || "$mode" == recover ]] || { echo 'mode must be detached, crash or recover' >&2; exit 2; }
run_probe() {
  # The project-view path is evaluated by the confined child, not this shell.
  # shellcheck disable=SC2016
  "$SYDGUARD_BIN" run --backend native --directory "$SYDGUARD_FIXTURE_PROJECT" \
    --syd /usr/local/libexec/sydguard-syd-3.59.0 --config "$profile" --project-id "$SYDGUARD_PROJECT_ID" \
    --expected-revision "$SYDGUARD_PROFILE_REVISION" --no-network -- /bin/sh -c 'printf "%s\n" "$PWD"'
}
if [[ "$mode" == recover ]]; then
  : "${SYDGUARD_EXPECT_SLOT:?set to the fixture slot name printed by crash mode after separately inspecting/cleaning scratch}"
  prefix="uid-$(id -u)-slot-"
  [[ "$SYDGUARD_EXPECT_SLOT" == "$prefix"* ]] || { echo 'unexpected slot UID' >&2; exit 2; }
  index="${SYDGUARD_EXPECT_SLOT#"$prefix"}"
  [[ "$index" =~ ^([0-9]|[12][0-9]|3[01])$ ]] || { echo 'invalid slot index' >&2; exit 2; }
  location="$(run_probe)"
  [[ "$location" == "/run/sydguard-launch/${SYDGUARD_EXPECT_SLOT}.anchor/project" ]] || { echo 'expected slot was not recovered/reused' >&2; exit 1; }
  echo 'Verified selected slot recovered and reused after separately inspected cleanup.'
  exit 0
fi
work="$(mktemp -d)"
cli_pid=''
cleanup() {
  if [[ -n "$cli_pid" ]] && kill -0 "$cli_pid" 2>/dev/null; then kill -TERM "$cli_pid" 2>/dev/null || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
# The background command closes its inherited output and proves setsid/exec by
# writing its own ready marker inside the selected run's separate scratch.
# shellcheck disable=SC2016
payload='set -eu
/usr/bin/setsid /bin/sh -c '\''printf ready > "$1"; exec /bin/sleep 120'\'' fixture "$SYDGUARD_TMPDIR/ready" <&- >&- 2>&- &
child=$!
i=0
while [ ! -f "$SYDGUARD_TMPDIR/ready" ]; do i=$((i+1)); [ "$i" -lt 200 ] || exit 91; /bin/sleep 0.02; done
printf "%s\n" "$child"
if [ "$1" = crash ]; then /bin/sleep 120; fi'
"$SYDGUARD_BIN" run --backend native --directory "$SYDGUARD_FIXTURE_PROJECT" \
  --syd /usr/local/libexec/sydguard-syd-3.59.0 --config "$profile" --project-id "$SYDGUARD_PROJECT_ID" \
  --expected-revision "$SYDGUARD_PROFILE_REVISION" --no-network -- /bin/sh -c "$payload" fixture "$mode" >"$work/out" 2>"$work/err" &
cli_pid=$!
for ((i=0; i<300; i++)); do
  [[ -s "$work/out" ]] && break
  if ! kill -0 "$cli_pid" 2>/dev/null; then cat "$work/err" >&2; echo 'launch failed before descendant readiness' >&2; exit 1; fi
  sleep 0.05
done
[[ -s "$work/out" ]] || { cat "$work/err" >&2; echo 'descendant readiness timed out' >&2; exit 1; }
IFS= read -r child <"$work/out"
[[ "$child" =~ ^[0-9]+$ ]] || { echo 'unexpected descendant identifier' >&2; exit 1; }
cgroup=''
if [[ "$mode" == crash ]]; then
  cgroup="$(awk -F: '$1 == "0" && $2 == "" {print $3}' "/proc/$child/cgroup")"
  [[ "$cgroup" == "/sydguard-launch/uid-$(id -u)-slot-"* ]] || { echo 'unexpected descendant cgroup' >&2; exit 1; }
  printf 'READY: CLI PID %s; detached child PID %s; cgroup %s\n' "$cli_pid" "$child" "$cgroup" >&2
  printf 'Administrator: independently identify the fixed disposable root launch helper belonging to this CLI, verify PID/start identity, and SIGKILL that helper now. This script does not invoke sudo or kill a root process.\n' >&2
fi
for ((i=0; i<1200; i++)); do
  if ! kill -0 "$cli_pid" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$cli_pid" 2>/dev/null; then cat "$work/err" >&2; echo 'launcher did not terminate in time' >&2; exit 1; fi
status=0
wait "$cli_pid" || status=$?
cli_pid=''
if [[ "$mode" == detached && "$status" != 0 ]]; then cat "$work/err" >&2; echo 'foreground exit failed' >&2; exit 1; fi
if [[ "$mode" == crash && "$status" == 0 ]]; then echo 'root-helper crash was not observed' >&2; exit 1; fi
for ((i=0; i<200; i++)); do
  if [[ ! -e "/proc/$child/stat" ]]; then break; fi
  state="$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null || true)"
  [[ "$state" == Z || -z "$state" ]] && break
  sleep 0.05
done
if [[ -e "/proc/$child/stat" ]]; then
  state="$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null || true)"
  [[ "$state" == Z || -z "$state" ]] || { echo 'detached descendant still running' >&2; exit 1; }
fi
if [[ -n "$cgroup" ]]; then
  events="/sys/fs/cgroup${cgroup}/cgroup.events"
  for ((i=0; i<200; i++)); do
    [[ ! -e "$events" ]] && break
    grep -qx 'populated 0' "$events" && break
    sleep 0.05
  done
  if [[ -e "$events" ]] && ! grep -qx 'populated 0' "$events"; then echo 'cgroup remained populated' >&2; exit 1; fi
  slot="${cgroup##*/}"
  anchor="/run/sydguard-launch/${slot}.anchor"
  if [[ -d "$anchor" ]]; then
    location="$(run_probe)"
    [[ "$location" != "$anchor/project" ]] || { echo 'dirty slot was unexpectedly reused' >&2; exit 1; }
    printf 'Dirty slot %s was not reused. Administrator must inspect its exact fixture-owned identities and separately clean only verified user scratch. Then rerun with SYDGUARD_LIFECYCLE_CASE=recover SYDGUARD_EXPECT_SLOT=%s.\n' "$slot" "$slot" >&2
  else
    printf 'Cgroup and anchor already cleaned. Verify reuse with SYDGUARD_LIFECYCLE_CASE=recover SYDGUARD_EXPECT_SLOT=%s.\n' "$slot" >&2
  fi
fi
printf 'Lifecycle %s fixture passed; inspect journals and mount cleanup separately.\n' "$mode"
