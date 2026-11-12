#!/usr/bin/env bash
# Opt-in, ordinary-UID fixture only. Parent must separately review/install the
# immutable helpers, enroll a disposable ext4 project and explicitly review a
# recursive project-read/no-network profile before invoking this script.
set -euo pipefail
: "${SYDGUARD_MANAGED_SMOKE:?set to 1 after disposable setup}"
[[ "$SYDGUARD_MANAGED_SMOKE" == 1 ]] || { echo 'explicit opt-in required' >&2; exit 2; }
: "${SYDGUARD_BIN:?absolute unprivileged CLI path required}"
: "${SYDGUARD_TEST_SYD:?absolute static Syd path required}"
: "${SYDGUARD_FIXTURE_PROJECT:?absolute disposable registered project path required}"
: "${SYDGUARD_PROJECT_ID:?registered project ID required}"
: "${SYDGUARD_PROFILE_REVISION:?reviewed exact revision required}"
profile="${SYDGUARD_PROFILE_NAME:-default}"
[[ "$SYDGUARD_BIN" == /* && "$SYDGUARD_FIXTURE_PROJECT" == /* ]] || { echo 'absolute paths required' >&2; exit 2; }
[[ "$SYDGUARD_TEST_SYD" == /usr/local/libexec/sydguard-syd-3.59.0 ]] || { echo 'fixed immutable engine path required' >&2; exit 2; }
fixture="$(mktemp -d "$SYDGUARD_FIXTURE_PROJECT/.sydguard-smoke-XXXXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
printf 'selected-read-ok' > "$fixture/visible"
relative="${fixture##*/}/visible"
# The enclosed script expands its variables only inside the confined child.
# shellcheck disable=SC2016
output="$("$SYDGUARD_BIN" run --backend native --directory "$SYDGUARD_FIXTURE_PROJECT" --syd "$SYDGUARD_TEST_SYD" --config "$profile" --project-id "$SYDGUARD_PROJECT_ID" --expected-revision "$SYDGUARD_PROFILE_REVISION" --no-network -- /bin/sh -c '
  set -eu
  [ "$(cat "$1")" = selected-read-ok ]
  [ "$SYDGUARD_PROFILE_NAME" = "$2" ]
  [ "$SYDGUARD_PROFILE_REVISION" = "$3" ]
  [ -n "$(cat "$SYDGUARD_SELECTED_PROFILE")" ]
  if printf changed > "$1"; then echo unexpected-project-write >&2; exit 91; fi
  printf selected-read-only-ok
' fixture "$relative" "$profile" "$SYDGUARD_PROFILE_REVISION")"
[[ "$output" == selected-read-only-ok ]] || { printf 'unexpected workload output: %s\n' "$output" >&2; exit 1; }
[[ "$(cat "$fixture/visible")" == selected-read-ok ]] || { echo 'fixture file changed' >&2; exit 1; }
printf 'Selected-profile read-only smoke passed; namespace/rename adversarial fixtures remain separate.\n'
