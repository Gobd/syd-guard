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
cd "$DIR" && git init -q || exit 1
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
sydguard -- sh -c 'curl -s -m 20 -o /dev/null -w "%{http_code}\n" https://example.com; curl -s -m 5 -o /dev/null -w "%{http_code}\n" --noproxy "*" https://example.org; curl -s -m 5 --noproxy "" -o /dev/null -w "%{http_code}\n" http://127.0.0.1:22/ ; curl -s -m 5 -o /dev/null -w "%{http_code}\n" https://localhost.localdomain/' > out3 2>&1
check "approved host works through TUN" "sed -n 2p out3 | grep -q 200"
check "direct connection (no proxy) to an unapproved host fails" "sed -n 3p out3 | grep -q 000"
check "host loopback is isolated" "sed -n 4p out3 | grep -q 000"
sydguard -- sh -c 'curl -s -m 30 -o /dev/null -w "%{http_code}\n" https://github.com' > out3b 2>&1 &
sleep 2
check "unknown host paused as a card" "cards | grep -q 'hosts https://github.com:443 1'"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"hosts\",\"pattern\":\"https://github.com\"}" >/dev/null
wait; check "paused request continued after approval" "tail -1 out3b | grep -q 200"

sydguard -- sh -c 'curl -s -m 10 -o /dev/null -w "%{http_code}\n" --connect-to other.example:443:example.com:443 https://other.example; echo "exit=$?"' > out3c 2>&1
check "TLS name must match the approved host (no domain fronting)" "! grep -q '^200' out3c"

echo "4. two rules files in one folder (--rules)"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$DIR/.sydguard/reader.json\",\"kind\":\"read\",\"pattern\":\"$SECRET/**\"}" >/dev/null
sydguard --rules reader -- cat "$SECRET/a.txt" > out4a 2>&1
sydguard -- cat "$SECRET/a.txt" > out4b 2>&1
check "--rules reader can read" "grep -q top-secret out4a"
check "default rules can't" "grep -q 'Permission denied' out4b"
sydguard --rules reader -- sh -c "echo x > .sydguard/reader.json" > out4c 2>&1
check "agent can't edit its --rules file" "grep -q 'Permission denied' out4c"

echo "4b. only the launch folder is writable"
mkdir -p "$DIR/sub"
(cd "$DIR/sub" && sydguard -- sh -c 'echo ok > here.txt && echo x > ../above.txt' > ../out4d 2>&1)
check "launch folder writable" "[ -f '$DIR/sub/here.txt' ]"
check "its parent is not" "grep -q 'above.txt: Permission denied' out4d"

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
mkdir -p "$DIR/l" && cd "$DIR/l" && git init -q || exit 1
sydguard --learn -- cat "$SECRET/a.txt" > out7 2>&1
check "learn allowed the read" "grep -q top-secret out7"
check "rule saved for next time" "grep -q 'sydguard-e2e-secret' .sydguard.json"
sydguard -- cat "$SECRET/a.txt" > out7b 2>&1
check "normal run uses learned rule" "grep -q top-secret out7b"

echo "8. synthetic DNS: exact host/port approvals without a proxy"
cd "$DIR" || exit 1
sydguard -- sh -c 'curl -s -m 25 --noproxy "*" -o /dev/null -w "%{http_code}\n" https://example.net' > out8 2>&1 &
sleep 2
check "TLS connection became a host/port card" "cards | grep -q 'hosts https://example.net:443'"
api /api/allow "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"hosts\",\"pattern\":\"tcp://example.net:443\"}" >/dev/null
wait; check "raw HTTPS (no proxy) works after approving the name" "tail -1 out8 | grep -q 200"
sydguard -- sh -c 'curl -s -m 8 --noproxy "*" -o /dev/null -w "%{http_code}\n" http://example.net' > out8b 2>&1
check "other port of the same host still blocked" "tail -1 out8b | grep -q 000"
api /api/remove "{\"scope\":\"rules\",\"file\":\"$R\",\"kind\":\"hosts\",\"pattern\":\"tcp://example.net:443\"}" >/dev/null
sydguard -- sh -c 'curl -s -m 6 --noproxy "*" -o /dev/null -w "%{http_code}\n" https://example.net' > out8c 2>&1
check "removing the rule blocks it again" "tail -1 out8c | grep -q 000"
sydguard -- sh -c 'getent hosts not-approved.example.org || echo refused' > out8d 2>&1
check "unapproved A/AAAA names receive local synthetic identities" "grep -q 'fd53:' out8d"

echo "9. node_modules stays on the VM disk"
mkdir -p "$DIR/web" && echo '{}' > "$DIR/web/package.json"
sydguard -- sh -c 'echo built > web/node_modules/artifact.txt && cat web/node_modules/artifact.txt' > out9 2>&1
check "agent can write node_modules" "grep -q built out9"
check "nothing written into the project's node_modules" "[ ! -e '$DIR/web/node_modules/artifact.txt' ]"
check "it lives in the VM overlay cache" "find '$HOME/.cache/sydguard/overlay' -name artifact.txt | grep -q ."

echo "9b. dev servers the agent starts are reachable from outside"
( timeout 30 sydguard -- sh -c 'python3 -m http.server 18770 --bind 0.0.0.0 >/dev/null 2>&1 & sleep 12' >/dev/null 2>&1 & )
for _ in $(seq 1 20); do curl -s -m 1 -o /dev/null http://127.0.0.1:18770/ && break; sleep 0.5; done
check "agent's dev server reachable on the VM loopback" "[ \"\$(curl -s -m 3 -o /dev/null -w %{http_code} http://127.0.0.1:18770/)\" = 200 ]"
sleep 12

echo "10. --local-port for a trusted helper"
python3 -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1 & srv=$!
sleep 0.5
sydguard --local-port 18765 -- curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18765/ > out10 2>&1
sydguard -- curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18765/ > out10b 2>&1
kill $srv
check "allowed with --local-port" "tail -1 out10 | grep -q 200"
check "blocked without it" "tail -1 out10b | grep -q 000"

# Leave nothing behind: scratch projects and their trust records.
for f in "$HOME"/.config/sydguard/trusted/*; do grep -q "$DIR" "$f" 2>/dev/null && rm -f "$f"; done
rm -rf "$DIR" "$SECRET"

echo
echo "passed $pass, failed $failed"
[ "$failed" -eq 0 ]
