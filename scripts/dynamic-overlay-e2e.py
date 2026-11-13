#!/usr/bin/env python3
"""Real-Syd deny-first overlays: no runtime Python dependency.
Run with matching engine/helper; E2E_LANDLOCK=1 repeats with a kernel ceiling.
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
root = Path(tempfile.mkdtemp(prefix=".sgg-", dir=Path.home()))
home, project, sibling, bad = [root / n for n in ("home", "project", "sibling", "bad")]
for p in (home, project, sibling, bad, project / "fresh", project / "plain", project / "alias", project / "rust", project / "manual", project / "rename-source"):
    p.mkdir()
(sibling / "Cargo.toml").write_text("[package]\nname='probe'\nversion='0.1.0'\n")
(bad / "Cargo.toml").write_text("[package]\nname='bad'\nversion='0.1.0'\n")
(bad / "target").symlink_to(sibling, target_is_directory=True)
if os.getenv("E2E_LANDLOCK"):
    config = home / ".config/sydguard"
    config.mkdir(parents=True)
    (config / "config.json").write_text(json.dumps({"landlock": {"enabled": True, "write": [str(sibling), str(bad)]}}))
state = home / ".local/state/sydguard"
env = {**os.environ, "HOME": str(home)}


def api(path, data=None):
    conn = http.client.HTTPConnection("localhost", timeout=40)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(40)
    conn.sock.connect(str(state / "daemon.sock"))
    conn.request("GET" if data is None else "POST", path, None if data is None else json.dumps(data), {"Content-Type": "application/json"})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    assert response.status == 200, body
    return body


def wait_for(fn):
    end = time.monotonic() + 40
    while time.monotonic() < end:
        try:
            result = fn()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise AssertionError("timeout; artifacts: " + str(root))


agent = project / "agent.py"
agent.write_text('''import os, time, sys, subprocess
from pathlib import Path
sibling, binary = Path(sys.argv[1]), sys.argv[2]
def retry(fn):
    end = time.monotonic() + 30
    while True:
        try: return fn()
        except (PermissionError, FileNotFoundError, FileExistsError):
            if time.monotonic() > end: raise
            time.sleep(.1)
def blocked(fn):
    try: fn()
    except PermissionError: return
    raise AssertionError("protected operation unexpectedly succeeded")
Path("ready").touch()
while not Path("go").exists(): time.sleep(.1)
# The driver created an unmounted host directory AFTER startup. Even O_PATH
# must be denied until a verified overlay is installed; no original dirfd leaks.
blocked(lambda: os.open("fresh/node_modules", os.O_PATH | os.O_DIRECTORY))
retry(lambda: os.makedirs("fresh/node_modules", exist_ok=True))
assert not Path("fresh/node_modules/host-sentinel").exists()
Path("fresh/node_modules/installed").write_text("overlay")
# No explicit overlay command: creating a package after startup is intercepted.
Path("new-package").mkdir()
retry(lambda: os.makedirs("new-package/node_modules", exist_ok=True))
Path("new-package/node_modules/automatic").write_text("overlay")
# A target without a manifest stays blocked. Creating Cargo.toml then retrying
# triggers automatic mounting rather than falling back to host storage.
blocked(lambda: Path("rust/target").mkdir())
Path("rust/Cargo.toml").write_text("[package]\\nname='probe'\\nversion='0.1.0'\\n")
retry(lambda: os.makedirs("rust/target", exist_ok=True))
Path("rust/target/built").write_text("overlay")
blocked(lambda: Path("manual/target").mkdir())
Path("force-needed").touch()
while not Path("force-ready").exists(): time.sleep(.1)
retry(lambda: os.makedirs("manual/target", exist_ok=True))
Path("manual/target/forced").write_text("overlay")
# The mkdir-only experiment allowed symlinks: the full guard must refuse them.
blocked(lambda: Path("alias/node_modules").symlink_to(Path("plain").absolute(), target_is_directory=True))
blocked(lambda: Path("rename-source").rename("alias/node_modules"))
# Moving a mounted parent must not leave a stale pathname exemption.
blocked(lambda: Path("fresh").rename("moved"))
(sibling / "target/artifact").write_text("overlay")
subprocess.run([binary, "overlay", "add", "fresh/node_modules"], check=True)
Path("done").touch()
while not Path("revoked").exists(): time.sleep(.1)
blocked(lambda: (sibling / "target/after-revoke").write_text("leak"))
Path("revoked-ok").touch()
while not Path("restarted").exists(): time.sleep(.1)
assert Path("fresh/node_modules/installed").read_text() == "overlay"
subprocess.run([binary, "overlay", "add", "fresh/node_modules"], check=True)
Path("restart-ok").touch()
while not Path("finish").exists(): time.sleep(.1)
''')
log = open(root / "run.log", "w")
proc = subprocess.Popen([binary, "--backend", "native", "--", "/usr/bin/python3", str(agent), str(sibling), binary],
                        cwd=project, env=env, stdout=log, stderr=log, start_new_session=True)
passed = False
try:
    wait_for(lambda: (project / "ready").exists())
    original = api("/api/state")["sessions"][0]
    result = api("/api/allow", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "write", "pattern": str(sibling) + "/***"})
    assert all(s["applied"] for s in result["sessions"]), result
    (project / "fresh/node_modules").mkdir()
    (project / "fresh/node_modules/host-sentinel").write_text("host")
    (project / "go").touch()
    wait_for(lambda: (project / "force-needed").exists())
    wait_for(lambda: any(c.get("overlayPath") == str(project / "manual/target") for c in api("/api/state")["cards"]))
    forced = api("/api/overlay", {"Session": original["id"], "Path": str(project / "manual/target")})
    assert forced["exit"] == 0, forced
    (project / "force-ready").touch()
    wait_for(lambda: (project / "done").exists())
    for rel in ("fresh/node_modules/installed", "new-package/node_modules/automatic", "rust/target/built", "manual/target/forced", "plain/installed"):
        assert not (project / rel).exists(), "host pollution: " + rel
    assert not (sibling / "target/artifact").exists()
    assert not (project / "alias/node_modules").is_symlink()
    assert (project / "fresh/node_modules/host-sentinel").read_text() == "host"
    result = api("/api/remove", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "write", "pattern": str(sibling) + "/***"})
    assert all(s["applied"] for s in result["sessions"]), result
    (project / "revoked").touch()
    wait_for(lambda: (project / "revoked-ok").exists())
    daemon = int((state / "daemon.pid").read_text())
    os.kill(daemon, signal.SIGKILL)
    wait_for(lambda: int((state / "daemon.pid").read_text()) != daemon and api("/api/state")["sessions"])
    assert api("/api/state")["sessions"][0]["sydPid"] == original["sydPid"]
    (project / "restarted").touch()
    wait_for(lambda: (project / "restart-ok").exists())
    result = api("/api/allow", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "write", "pattern": str(bad) + "/***"})
    assert result["sessions"] and not any(s["applied"] for s in result["sessions"]), result
    (project / "finish").touch()
    assert proc.wait(timeout=15) == 0
    failed = subprocess.run([binary, "--backend", "native", "--", "/bin/true"], cwd=project, env=env, capture_output=True, text=True, timeout=30)
    assert failed.returncode != 0 and "overlay" in failed.stderr, failed.stderr
    api("/api/remove", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "write", "pattern": str(bad) + "/***"})
    check = 'from pathlib import Path; assert Path("manual/target/forced").read_text() == "overlay"; assert Path("fresh/node_modules/installed").read_text() == "overlay"'
    restarted = subprocess.run([binary, "--backend", "native", "--", "/usr/bin/python3", "-c", check], cwd=project, env=env, capture_output=True, text=True, timeout=30)
    assert restarted.returncode == 0, restarted.stderr
    # Installed agents may themselves live in node_modules. Their authorized
    # read/exec access must work without mounting an empty directory over them.
    tool = root / "tools/node_modules/fake-agent/run.sh"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\nif printf bad > '" + str(tool.parent / "write-attempt") + "'; then exit 7; fi\nprintf ready > runtime-ok\n")
    tool.chmod(0o755)
    shim = root / "fake-agent"
    shim.symlink_to(tool)
    runtime_probe = subprocess.run([binary, "--backend", "native", "--", str(shim)], cwd=project, env=env, capture_output=True, text=True, timeout=30)
    assert runtime_probe.returncode == 0, runtime_probe.stderr
    assert (project / "runtime-ok").read_text() == "ready"
    assert not (tool.parent / "write-attempt").exists(), "toolchain became writable"
    passed = True
    print("PASS: deny-first O_PATH, automatic mkdir mounting, late Cargo manifest, symlink/rename refusal, ancestor locks, revocation, explicit verification and same-PID restart; Landlock=" + str(bool(os.getenv("E2E_LANDLOCK"))))
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
