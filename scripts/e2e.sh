#!/usr/bin/env bash
# Acceptance test against the real Syd engine. Run inside the Linux VM:
#   scripts/e2e.sh
# Uses a scratch project under $E2E_DIR (default ~/.cache/sydguard-e2e).
set -uo pipefail
SOCK="$HOME/.local/state/sydguard/daemon.sock"
DIR="${E2E_DIR:-$HOME/.cache/sydguard-e2e}"
SECRET="$HOME/.cache/sydguard-e2e-secret"
pass=0 failed=0
ok() { echo "  ✓ $*"; pass=$((pass + 1)); }
bad() { echo "  ✗ $*"; failed=$((failed + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
api() { if [ -n "${2:-}" ]; then curl -s --unix-socket "$SOCK" -X POST -d "$2" "http://x$1"; else curl -s --unix-socket "$SOCK" "http://x$1"; fi; }
cards() { api /api/state | python3 -c 'import json,sys; s=json.load(sys.stdin); [print(c["kind"], c["target"], c["waiting"], c["rulesFile"]) for c in s["cards"]]'; }
status() { api /api/state | python3 -c 'import json,sys; s=json.load(sys.stdin); [print(x["status"]) for x in s["sessions"]]'; }
wait_for() { for _ in $(seq 1 40); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.25; done; return 1; }

rm -rf "$DIR" "$SECRET"; mkdir -p "$DIR" "$SECRET"; echo top-secret > "$SECRET/a.txt"
cd "$DIR" && git init -q
sydguard daemon-ensure >/dev/null
R="$DIR/.sydguard.json"

echo "1. same-PID file approve → applied → revoke"
cat > agent.sh <<EOF
prev=""; for i in \$(seq 1 60); do
  cur=\$(cat "$SECRET/a.txt" >/dev/null 2>&1 && echo ALLOWED || echo blocked)
  [ "\$cur" != "\$prev" ] && echo "\$\$ \$cur"; prev=\$cur; sleep 0.25
done
EOF
sydguard -- bash agent.sh > out1 2>&1 &
wait_for out1 "blocked"
sleep 0.5
check "denial became a card" "cards | grep -q 'read $SECRET/a.txt'"
res=$(api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"read\",\"pattern\":\"$SECRET/**\"}")
check "allow saved and applied live" "echo '$res' | grep -q '\"applied\":true'"
wait_for out1 "ALLOWED"; check "same PID now reads the file" "grep -q ALLOWED out1"
res=$(api /api/remove "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"read\",\"pattern\":\"$SECRET/***\"}")
check "remove applied live" "echo '$res' | grep -q '\"applied\":true'"
sleep 1; check "same PID blocked again" "tail -1 out1 | grep -q blocked"
check "one PID throughout" "[ \$(cut -d' ' -f1 out1 | grep -v sydguard: | sort -u | wc -l) -eq 1 ]"
wait

echo "2. tamper protection"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"hosts\",\"pattern\":\"example.com\"}" >/dev/null
sydguard -- sh -c "echo '{\"write\":[\"/***\"]}' > .sydguard.json; mkdir -p .git/hooks; echo x > .git/hooks/pre-commit; ln .sydguard.json alias.json && echo '{\"hosts\":[\"*\"]}' > alias.json; echo done" > out2 2>&1
check "direct write to rules file denied" "grep -q 'sydguard.json: Permission denied' out2"
check ".git/hooks write denied" "grep -q 'pre-commit: Permission denied' out2"
check "rules file unchanged by path" "grep -q example.com $R"
if [ -e alias.json ]; then
  st=$(api /api/state | python3 -c 'import json,sys; s=json.load(sys.stdin); print([f.get("error","") for f in s["files"] if f["path"].endswith(".sydguard.json")])')
  check "hardlinked rules file is refused (not used)" "echo '$st' | grep -q 'hard links'"
  rm -f alias.json
else
  ok "hard link to rules file could not be created"
fi

echo "3. web by host name; private/local addresses"
sydguard -- sh -c 'curl -s -m 20 -o /dev/null -w "%{http_code}\n" https://example.com; curl -s -m 5 -o /dev/null -w "%{http_code}\n" --noproxy "*" https://example.com; curl -s -m 5 --noproxy "" -o /dev/null -w "%{http_code}\n" http://127.0.0.1:22/ ; curl -s -m 5 -o /dev/null -w "%{http_code}\n" https://localhost.localdomain/' > out3 2>&1
check "approved host works through proxy" "sed -n 2p out3 | grep -q 200"
check "direct connection (no proxy) fails" "sed -n 3p out3 | grep -q 000"
check "loopback via proxy refused" "sed -n 4p out3 | grep -q 403"
sydguard -- sh -c 'curl -s -m 30 -o /dev/null -w "%{http_code}\n" https://github.com' > out3b 2>&1 &
sleep 2
check "unknown host paused as a card" "cards | grep -q 'hosts https://github.com:443 1'"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"hosts\",\"pattern\":\"https://github.com\"}" >/dev/null
wait; check "paused request continued after approval" "tail -1 out3b | grep -q 200"

echo "4. two rules files in one folder (--rules)"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$DIR/.sydguard/reader.json\",\"kind\":\"read\",\"pattern\":\"$SECRET/**\"}" >/dev/null
sydguard --rules reader -- cat "$SECRET/a.txt" > out4a 2>&1
sydguard -- cat "$SECRET/a.txt" > out4b 2>&1
check "--rules reader can read" "grep -q top-secret out4a"
check "default rules can't" "grep -q 'Permission denied' out4b"
sydguard --rules reader -- sh -c "echo x > .sydguard/reader.json" > out4c 2>&1
check "agent can't edit its --rules file" "grep -q 'Permission denied' out4c"

echo "5. daemon restart while an agent runs"
sydguard -- bash agent.sh > out5 2>&1 &
wait_for out5 blocked
pkill -f "sydguard daemon$"; sleep 0.3; sydguard daemon-ensure >/dev/null
check "running session adopted" "api /api/state | grep -q 'agent.sh'"
res=$(api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"read\",\"pattern\":\"$SECRET/**\"}")
check "live update works after restart" "echo '$res' | grep -q '\"applied\":true'"
wait_for out5 ALLOWED; check "agent sees it" "grep -q ALLOWED out5"
api /api/remove "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"read\",\"pattern\":\"$SECRET/***\"}" >/dev/null
wait

echo "6. failed update is reported, not hidden"
sydguard -- sleep 6 > out6 2>&1 &
sleep 1.5
ipc=$(api /api/state | python3 -c 'import json,sys; s=json.load(sys.stdin); print([x["id"] for x in s["sessions"] if x["cmd"][0]=="sleep"][0])')
pkill -STOP -f "syd.*sessions/$ipc.syd-3" # freeze Syd: its IPC can't answer
res=$(api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"read\",\"pattern\":\"/opt/nothing/**\"}")
pkill -CONT -f "syd.*sessions/$ipc.syd-3"
check "response says NOT applied" "echo '$res' | grep -q '\"applied\":false'"
check "session marked unknown" "status | grep -q unknown"
wait

echo "7. learn mode saves rules"
mkdir -p "$DIR/l" && cd "$DIR/l" && git init -q
sydguard --learn -- cat "$SECRET/a.txt" > out7 2>&1
check "learn allowed the read" "grep -q top-secret out7"
check "rule saved for next time" "grep -q 'sydguard-e2e-secret' .sydguard.json"
sydguard -- cat "$SECRET/a.txt" > out7b 2>&1
check "normal run uses learned rule" "grep -q top-secret out7b"

echo
echo "passed $pass, failed $failed"
[ "$failed" -eq 0 ]
