#!/usr/bin/env python3
"""Linux integration test. Run `sydguard setup`, then pass the built binary.
Uses example.com for real TLS; all state is isolated under a temporary HOME.
"""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = os.path.abspath(sys.argv[1])
root = Path(tempfile.mkdtemp(prefix="sydguard-network-"))
home, project = root / "home", root / "project"
home.mkdir()
project.mkdir()
state_dir = home / ".local/state/sydguard"


def api(path, data=None):
    conn = http.client.HTTPConnection("localhost", timeout=10)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(10)
    conn.sock.connect(str(state_dir / "daemon.sock"))
    conn.request("GET" if data is None else "POST", path, None if data is None else json.dumps(data), {"Content-Type": "application/json"})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    assert response.status == 200, body
    return body


def wait_for(fn, seconds=40):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = fn()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise AssertionError("timed out; artifacts: " + str(root))


tcp = socket.socket()
tcp.bind(("127.0.0.1", 0))
tcp.listen()
port = tcp.getsockname()[1]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", port))


def echo_tcp():
    while True:
        c, _ = tcp.accept()
        with c:
            c.sendall(c.recv(1024))


def echo_udp():
    while True:
        data, addr = udp.recvfrom(1024)
        udp.sendto(data, addr)


threading.Thread(target=echo_tcp, daemon=True).start()
threading.Thread(target=echo_udp, daemon=True).start()
agent = project / "agent.py"
agent.write_text('''import os, socket, ssl, time, subprocess
from pathlib import Path
port = int(os.environ["TEST_PORT"])
assert not os.environ.get("HTTPS_PROXY")
ips = [x[4][0] for x in socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)]
assert any(ip.startswith("198.18.") for ip in ips), ips
assert any(ip.startswith("fd53:") for ip in ips), ips

def check():
    for ip in ips:
        with socket.create_connection((ip, 443), timeout=20) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname="example.com") as tls:
                tls.sendall(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n")
                assert b"200" in tls.recv(4096).split(b"\\r\\n")[0]
    for host in ["127.0.0.1", "192.0.2.2"]: # loopback listeners AND gVisor flows
        with socket.create_connection((host, port), timeout=5) as c:
            c.sendall(b"tcp-check")
            assert c.recv(100) == b"tcp-check"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(5)
            c.sendto(b"udp-check", (host, port))
            assert c.recv(100) == b"udp-check"
check()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
    c.settimeout(1)
    c.sendto(b"not-authorized-by-https", ("198.18.0.1", 443))
    try:
        c.recv(100)
        raise AssertionError("HTTPS grant authorized UDP")
    except TimeoutError: pass

Path("before").touch()
while not Path("resume").exists(): time.sleep(.1)
check() # deliberately reuse cached synthetic addresses after restart
Path("after").touch()
while not Path("finish").exists(): time.sleep(.1)
''')
# Pass a harmless test variable through the command argv, not config secrets.
agent.write_text(agent.read_text().replace('int(os.environ["TEST_PORT"])', str(port)).replace('Path("before").touch()', 'subprocess.run(' + repr([binary, "cmd", "--list"]) + ', check=True)\nPath("before").touch()'))
log = open(root / "run.log", "w")
proc = subprocess.Popen([binary, "--backend", "native", *(["--landlock"] if os.environ.get("E2E_LANDLOCK") == "1" else []), "--local-port", str(port), "--", "/usr/bin/python3", str(agent)], cwd=project, env={**os.environ, "HOME": str(home)}, stdout=log, stderr=log, start_new_session=True)
try:
    pending = wait_for(lambda: next((c for c in api("/api/state")["cards"] if c["kind"] == "hosts"), None))
    assert pending["target"] == "https://example.com:443", pending
    api("/api/allow", {"card": pending["id"], "scope": "rules", "file": str(project / ".sydguard.json"), "kind": "hosts", "pattern": "https://example.com:443"})
    jobs = wait_for(lambda: api("/api/jobs"))
    assert jobs[0]["op"] == "list", jobs
    api("/api/jobs/result", {"ID": jobs[0]["id"], "Result": {"exit": 0, "commands": []}})
    wait_for(lambda: (project / "before").exists())
    state = api("/api/state")
    assert any(c["target"] == "udp://example.com:443" for c in state["cards"]), state["cards"]
    session = state["sessions"][0]
    assert any(c["protocol"] == "tcp" and c["port"] == "443" for c in session["connections"]), session
    applied = api("/api/allow", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "read", "pattern": "/opt/sydguard-network-test"})
    assert all(s["applied"] for s in applied["sessions"]), applied
    ns_before = os.readlink(f'/proc/{session["sydPid"]}/ns/net')
    old_pid = int((state_dir / "daemon.pid").read_text())
    os.kill(old_pid, signal.SIGKILL)
    wait_for(lambda: int((state_dir / "daemon.pid").read_text()) != old_pid and api("/api/state")["sessions"])
    assert os.readlink(f'/proc/{session["sydPid"]}/ns/net') == ns_before
    applied = api("/api/remove", {"scope": "rules", "file": str(project / ".sydguard.json"), "kind": "read", "pattern": "/opt/sydguard-network-test"})
    assert all(s["applied"] for s in applied["sessions"]), applied
    (project / "resume").touch()
    wait_for(lambda: (project / "after").exists())
    rules = json.loads((project / ".sydguard.json").read_text())
    assert rules["hosts"] == ["https://example.com:443"], rules
    (project / "finish").touch()
    assert proc.wait(timeout=20) == 0
    print("PASS: exact approval, IPv4/IPv6 TLS, TCP/UDP isolation, broker, crash recovery, cached DNS, live IPC; " + str(root))
finally:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=15)
    try:
        api("/internal/quit", {})
    except OSError:
        pass
    log.close()
