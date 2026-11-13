# sydguard

Run an AI agent under unmodified upstream [Syd](https://gitlab.exherbo.org/sydbox/sydbox),
get a browser card for everything it isn't allowed to do, and approve/deny it.
Approvals and rule edits apply **live to the running agent** through Syd's IPC
socket, and are saved to the project's rules file.

```sh
make                       # builds bin/sydguard (+ Linux binaries it installs into Lima)
sydguard -- lambdap pi     # from any project under ~/Developer on the Mac
sydguard --learn -- pi     # permissive run that records suggestions to review
sydguard ui                # open the approvals UI
```

On macOS it uses Lima VM `ai-sandbox` (`--vm`, `$SYDGUARD_VM`), starts it if
stopped, creates it from `--lima FILE` (or a built-in default) if missing, copies
the matching Linux `sydguard` in, and runs the command in the same project path.
Inside Linux/WSL run `sydguard -- cmd` directly. A background daemon (auto-started,
`~/.local/state/sydguard/daemon.log`) serves the UI on `127.0.0.1:7878`.

## Usage

```sh
sydguard -- lambdap pi                 # rules: <git root>/.sydguard.json
sydguard --rules review -- lambdap pi  # rules: <git root>/.sydguard/review.json
sydguard --rules ~/r/strict.json -- codex
sydguard --learn -- lambdap claude     # allow all, save what it used, review later
sydguard --vm dev --lima ~/dev.yaml -- pi   # another VM (created from that file if missing)
sydguard ui                            # open the approvals UI
sydguard doctor                        # check engine + daemon
```

## Rules

`<git root>/.sydguard.json` by default (committable), or `--rules NAME|FILE`, plus
"all projects" rules in `~/.config/sydguard/global.json` on the Mac (mirrored to
every VM):

```json
{
  "read":    ["~/.cache/go-build/**", "/opt/tool/*"],
  "write":   ["~/.npm/**"],
  "hosts":   ["https://github.com", "*.githubusercontent.com", "tcp://db.example.com:5432"],
  "connect": ["140.82.112.3!22"],
  "ignore":  ["telemetry.example.com"]
}
```

- Built in (shown in the UI): system dirs read-only; the project and `/tmp`
  read+write. `write` = read + create/modify/delete/rename (not Syd's `all`).
- `hosts` are by name: `github.com` (any port/protocol), `https://github.com`
  (443), `http://x:8080`, `tcp://host:port`, `*.example.com` (subdomains). HTTPS is
  decided at CONNECT (host+port, not URL path). Hosts resolving to loopback or
  link-local/metadata addresses are never proxied; private/LAN addresses need an
  exact `protocol://host[:port]` rule. `connect` is raw IP/socket access for tools
  that ignore `HTTPS_PROXY`; prefer `hosts`.
- Protected: the sandbox can't read `~/.config/sydguard`, sydguard's state, `~/.ssh`,
  `~/.gnupg`, `~/.lima`, and can't modify rules files, `.sydguard/`, `~/.local/bin`,
  shell rc files, `.git/hooks`, `.git/config`. Grants overlapping these are refused,
  and every live update re-applies the denies in the same atomic batch.
- Integrity: sydguard only uses rules content whose hash it wrote or you trusted.
  A file changed any other way (editor, `git pull`, clone, a hard link) is shown in
  the UI / terminal and ignored until you trust it; files with extra hard links
  are refused.

## How it works

- **Mac:** `sydguard` starts/reuses the Lima VM, installs the matching Linux
  sydguard, and runs `sydguard` in the VM at the same project path. The UI server
  runs on the Mac (`127.0.0.1:7878`, token-protected) and reaches each running
  VM's daemon over its Unix socket forwarded through Lima's SSH — one UI for all
  VMs and agents. Nothing in a VM listens on TCP for the UI.
- **VM daemon** (Unix socket, auto-started): compiles a Syd profile per session,
  runs a per-session HTTP(S) proxy (the only network the agent may use), turns
  Syd's JSON denials (fd 3) into cards, and applies approvals/removals live through
  Syd's IPC as one atomic `load` per session. Each session shows **applied**,
  **updating** or **unknown**; a failed or unanswered update marks it unknown, stops
  further edits to it, and is reported in the UI — never shown as applied.
- File accesses are denied immediately and succeed on retry once applied. Web
  requests wait (up to 10 min) for your decision.

## Tests

`go test ./...` (rules, validation, protection, profile, trust store) and
`scripts/e2e.sh` inside the VM (real Syd: same-PID approve/revoke, tamper and hard
links, host approvals and local-address refusal, `--rules`, daemon restart, failed
update reporting, learn).

## Engine

Tested with upstream Syd 3.59.x, unmodified. `sydguard` probes candidates
(`$SYDGUARD_SYD`, `~/.local/opt/syd-3.59.0-static/bin/syd`, …) for the right
version and a working binary. `scripts/install-syd.sh` builds it statically with
pinned versions/checksums; the built-in Lima template runs it on first boot.

## Known limits

- Landlock is off: approvals can extend anywhere (no kernel ceiling); Syd's
  seccomp path checks do the enforcing.
- If the agent kills the daemon, approvals and its proxy stop (fail closed) until
  it restarts and re-adopts the session. Syd itself keeps enforcing.
- Revoking can't undo completed I/O or close already-open files/tunnels.
- Tools ignoring proxy settings get only `connect` (IP) rules. Some agent
  compatibility switches are on (TPE off, symlinks in group-writable dirs, W^X
  memory for JITs, non-PIE).
