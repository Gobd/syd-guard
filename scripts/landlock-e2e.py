#!/usr/bin/env python3
"""Real-Syd Linux test: optional Landlock, live grants, revocation and restart.
Run setup with the same binary first. Uses no external network services.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

binary = os.path.abspath(sys.argv[1])
# Deliberately NOT /tmp: /tmp is part of the normal writable runtime baseline.
root = Path(tempfile.mkdtemp(prefix=".sgll-", dir=Path.home()))
home, project, inside, outside = [root / n for n in ("home", "project", "inside", "outside")]
for p in (home, project, inside, outside):
    p.mkdir()
(project / "package.json").write_text("{}") # exercise the VM-local node_modules overlay
(inside / "secret").write_text("inside")
(outside / "secret").write_text("outside")
config = home / ".config/sydguard"
config.mkdir(parents=True)
(config / "config.json").write_text(json.dumps({"landlock": {"enabled": True, "write": [str(inside)]}}))
state_dir = home / ".local/state/sydguard"
env = {**os.environ, "HOME": str(home)}


def api(path, data=None, status=200):
    conn = http.client.HTTPConnection("localhost", timeout=10)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(10)
    conn.sock.connect(str(state_dir / "daemon.sock"))
    conn.request("GET" if data is None else "POST", path, None if data is None else json.dumps(data), {"Content-Type": "application/json"})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    assert response.status == status, body
    return body


def wait_for(fn, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = fn()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise AssertionError("timed out; inspect " + str(root))


agent = project / "agent.py"
agent.write_text('''from pathlib import Path
import time, sys
inside = Path(sys.argv[1])
Path("node_modules/artifact.txt").write_text("built")
assert Path("node_modules/artifact.txt").read_text() == "built"
while True:
    try:
        assert (inside / "secret").read_text() == "inside"
        break
    except PermissionError: time.sleep(.1)
Path("read-ok").touch()
while True:
    try:
        (inside / "output").write_text("written")
        break
    except PermissionError: time.sleep(.1)
Path("write-ok").touch()
while not Path("check-revoked").exists(): time.sleep(.1)
try:
    (inside / "secret").read_text()
    raise AssertionError("revoked read succeeded")
except PermissionError: pass
Path("revoked-ok").touch()
while not Path("finish").exists(): time.sleep(.1)
''')
log = open(root / "run.log", "w")
proc = subprocess.Popen([binary, "--backend", "native", "--", "/usr/bin/python3", str(agent), str(inside)], cwd=project, env=env, stdout=log, stderr=log, start_new_session=True)
passed = False
try:
    wait_for(lambda: any(c["kind"] == "read" and c["target"] == str(inside / "secret") for c in api("/api/state")["cards"]))
    rules = str(project / ".sydguard.json")

    def edit(op, kind, pattern, expected=200):
        return api("/api/" + op, {"scope": "rules", "file": rules, "kind": kind, "pattern": pattern}, expected)

    result = edit("allow", "read", str(outside) + "/***", 400)
    assert "Landlock ceiling" in result["error"], result
    for kind, marker in [("read", "read-ok"), ("write", "write-ok")]:
        result = edit("allow", kind, str(inside) + "/***")
        assert all(s["applied"] for s in result["sessions"]), result
        wait_for(lambda: (project / marker).exists())
    session = api("/api/state")["sessions"][0]
    assert session["landlock"]["enabled"]
    pid = int((state_dir / "daemon.pid").read_text())
    os.kill(pid, signal.SIGKILL)
    wait_for(lambda: int((state_dir / "daemon.pid").read_text()) != pid and api("/api/state")["sessions"])
    adopted = api("/api/state")["sessions"][0]
    assert adopted["sydPid"] == session["sydPid"] and adopted["landlock"] == session["landlock"]
    for kind in ("read", "write"):
        result = edit("remove", kind, str(inside) + "/***")
        assert all(s["applied"] for s in result["sessions"]), result
    (project / "check-revoked").touch()
    wait_for(lambda: (project / "revoked-ok").exists())
    (project / "finish").touch()
    assert proc.wait(timeout=15) == 0
    assert not (project / "node_modules/artifact.txt").exists(), "overlay leaked into project"

    # Learn mode permits the operation in Syd, but cannot widen Landlock.
    probe = project / "probe.py"
    probe.write_text('''from pathlib import Path
import sys
outside = Path(sys.argv[1])
blocked = sys.argv[2] == "blocked"
for op in [lambda: (outside / "secret").read_text(), lambda: (outside / "created").write_text("x")]:
    try:
        op()
        assert not blocked, "Landlock failed to restrict learn mode"
    except PermissionError:
        assert blocked, "explicit Landlock disable did not work"
print("probe passed")
''')
    for flag, expect in [("--landlock", "blocked"), ("--landlock=false", "allowed")]:
        run = subprocess.run([binary, "--backend", "native", flag, "--learn", "--rules", expect, "--", "/usr/bin/python3", str(probe), str(outside), expect], cwd=project, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        assert run.returncode == 0, run.stdout
    learned = project / ".sydguard/blocked.json"
    if learned.exists():
        assert str(outside) not in learned.read_text(), "kernel-denied operations became learned grants"
    passed = True
    print("PASS: opt-in ceiling, blocked outside grant, live read/write, same-PID revocation/restart, build overlays, learn-mode kernel enforcement, explicit disable")
finally:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=15)
    try:
        api("/internal/quit", {})
    except OSError:
        pass
    log.close()
    if passed:
        shutil.rmtree(root)
    else:
        print("Failure artifacts:", root, file=sys.stderr)
