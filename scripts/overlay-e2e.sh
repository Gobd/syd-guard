#!/usr/bin/env bash
# Live keepOnVM overlay acceptance test against the real Syd engine. Run inside
# the Lima VM (needs a host share, e.g. ~/Developer over virtiofs):
#   scripts/overlay-e2e.sh
# Uses a scratch folder on the share ($E2E_SHARE/.sg-ov-e2e) and checks that
# nothing reaches the host's copy.
set -uo pipefail
sydguard() { command sydguard --backend native "$@"; }
SOCK="$HOME/.local/state/sydguard/daemon.sock"
SHARE=${E2E_SHARE:-$(awk '$0 ~ / - virtiofs / {print $5; exit}' /proc/self/mountinfo)}
[ -n "$SHARE" ] || { echo "no host share found; set E2E_SHARE" >&2; exit 2; }
BASE=$SHARE/.sg-ov-e2e
P=$BASE/p Y=$BASE/y R=$P/.sydguard.json
pass=0 failed=0
ok() { echo "  ✓ $*"; pass=$((pass + 1)); }
bad() { echo "  ✗ $*"; failed=$((failed + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
api() { if [ -n "${2:-}" ]; then curl -s --unix-socket "$SOCK" -X POST -d "$2" "http://x$1"; else curl -s --unix-socket "$SOCK" "http://x$1"; fi; }
card_for() { api /api/state | python3 -c 'import json,sys; [print(c["id"]) for c in json.load(sys.stdin)["cards"] if c.get("overlay")==sys.argv[1]]' "$1" | head -1; }
wait_for() { for _ in $(seq 1 60); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.25; done; return 1; }
wait_card() { for _ in $(seq 1 40); do c=$(card_for "$1"); [ -n "$c" ] && { echo "$c"; return 0; }; sleep 0.25; done; return 1; }

rm -rf "$BASE"; mkdir -p "$P" "$Y"; cd "$P" && git init -q
# Forget only this test's saved folders.
python3 - "$HOME/.local/state/sydguard/overlays.json" "$BASE/" <<'PY'
import json, os, sys
f, base = sys.argv[1:]
if os.path.exists(f):
    json.dump([t for t in json.load(open(f)) if not t.startswith(base)], open(f, "w"))
PY
# Agent: keep trying to install a file into DIR/node_modules; report changes.
cat > "$P/agent.sh" <<'A'
d=$1; prev=""; for i in $(seq 1 120); do
  cur=$( (mkdir -p "$d/node_modules/a" && echo x > "$d/node_modules/a/f") 2>/dev/null && echo OK || echo blocked)
  [ "$cur" != "$prev" ] && echo "$i $cur"; prev=$cur
  [ "$cur" = OK ] && [ "${2:-}" = once ] && exit 0; sleep 0.25
done
A
sydguard daemon-ensure >/dev/null

echo "1. new folder in the project: blocked → Keep on VM → retry works, live"
sydguard -- bash "$P/agent.sh" "$P/web" > out1 2>&1 &
wait_for out1 blocked; check "first attempt blocked" "grep -q '1 blocked' out1"
check "nothing created on the host" "[ ! -e $P/web/node_modules/a ]"
c=$(wait_card "$P/web/node_modules"); check "one Keep on VM card" "[ -n '$c' ]"
res=$(api /api/overlay "{\"card\":\"$c\"}"); check "overlay applied: $res" "echo '$res' | grep -q '\"applied\":true'"
wait_for out1 OK; check "same agent's retry now succeeds" "grep -q OK out1"
check "host still has no file" "[ ! -e $P/web/node_modules/a/f ]"
check "file is on VM storage" "ls ~/.cache/sydguard/overlay/*/a/f >/dev/null 2>&1"
wait

echo "2. sibling folder granted later (not the project)"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"write\",\"pattern\":\"$Y/***\"}" > /dev/null
sydguard -- bash "$P/agent.sh" "$Y" > out2 2>&1 &
wait_for out2 blocked; check "sibling install blocked" "grep -q '1 blocked' out2"
check "sibling: nothing on host" "[ ! -e $Y/node_modules/a ]"
c=$(wait_card "$Y/node_modules")
res=$(api /api/overlay "{\"card\":\"$c\"}"); check "sibling overlay applied" "echo '$res' | grep -q '\"applied\":true'"
wait_for out2 OK; check "sibling retry succeeds" "grep -q OK out2"
check "sibling host still clean" "[ ! -e $Y/node_modules/a/f ]"
wait

echo "3. later session: saved folders work on the first try"
sydguard -- bash -c "bash $P/agent.sh $P/web once; bash $P/agent.sh $Y once" > out3 2>&1
check "both succeed immediately" "[ \$(grep -c '^1 OK' out3) -eq 2 ]"
check "host still clean" "[ ! -e $P/web/node_modules/a/f ] && [ ! -e $Y/node_modules/a/f ]"

echo "4. saved folder mounted live when a session gains write access"
api /api/remove "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"write\",\"pattern\":\"$Y/***\"}" > /dev/null
sydguard -- bash "$P/agent.sh" "$Y" > out4 2>&1 &
wait_for out4 blocked
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"write\",\"pattern\":\"$Y/***\"}" > /dev/null
wait_for out4 OK; check "works after the grant, no second ask" "grep -q OK out4"
check "host still clean" "[ ! -e $Y/node_modules/a/f ]"
wait

echo "5. VM disk unaffected; moves allowed"
sydguard -- bash -c "mkdir -p /tmp/sg-ov-vm/node_modules && echo x > /tmp/sg-ov-vm/node_modules/f && echo VMOK; mkdir -p $P/pkg && mv $P/pkg $P/pkg2 && echo MVOK" > out5 2>&1
check "node_modules on VM disk is writable" "grep -q VMOK out5"
check "moving project folders works" "grep -q MVOK out5"
rm -rf /tmp/sg-ov-vm

cd / && rm -rf "$BASE"
echo; echo "passed $pass, failed $failed"
[ "$failed" -eq 0 ]
