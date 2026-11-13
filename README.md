# sydguard

Run AI coding agents (Claude Code, Codex, Pi, …) under unmodified upstream
[Syd](https://gitlab.exherbo.org/sydbox/sydbox). Everything the agent isn't
allowed to do shows up in a browser UI; approve or deny it, edit rules by hand,
and every change applies **live to the running agent** and is saved to a rules
file the agent can't touch.

```sh
make install                             # sydguard + the Linux binaries it puts into VMs
cd ~/Developer/myproject
sydguard --learn -- claude               # first run: allow everything, save what it used
sydguard -- claude                       # then: enforce the rules file, approve the rest
sydguard ui                              # open the approvals UI (http://127.0.0.1:7878)
```

Where it runs:

- **Linux and WSL2**: directly (Syd is Linux-only). Add `--vm` (or `"vm"` in the
  config) to use a Lima VM anyway, as a second wall around your files.
- **Anywhere else (macOS)**: in a Lima VM at the **same path** as your project.
  sydguard starts the VM if stopped, creates it if missing (built-in default,
  `--lima FILE` or the config), installs the matching Linux sydguard and, once,
  the pinned Syd engine. All agents in a VM share it.

The UI runs on the machine where you type `sydguard` and covers its own agents
plus every running Lima VM.

## Usage

```
sydguard [flags] [--] command [args...]
  --rules NAME|FILE   rules file; default <git root>/.sydguard.json, NAME = .sydguard/NAME.json
                      (two agents in one folder can use different rules)
  --learn             allow everything; save what the command used into the rules file
  --local-port PORT   let the agent reach 127.0.0.1:PORT (a trusted helper you run outside)
  --vm NAME           run in this Lima VM ($SYDGUARD_VM, config, default ai-sandbox)
  --lima FILE         Lima file to create the VM from if missing ($SYDGUARD_LIMA, config, built in)
sydguard ui                open (and start) the approvals UI
sydguard status            UI server, daemons and VMs: running? which build? agents?
sydguard stop [--force]    stop the UI server and daemons (refuses while agents run)
sydguard stop VM...        shut down those Lima VMs;  --all: UI, daemons and every VM
sydguard restart           restart the UI server and daemons with this build
sydguard vm [-- cmd]       a shell (or command) in the VM, outside the sandbox
sydguard doctor | setup    check / install the pinned Syd engine
sydguard prepare           VM, engine, daemon and UI ready without running anything
```

Background processes: the **UI server** runs on the machine where you type
`sydguard` (started on demand); each machine that runs agents has a **daemon**
(per VM, started on demand). Both restart themselves when the binary changes.

## Config

`~/.config/sydguard/config.json` on the machine you run `sydguard` on (the sandbox
can't read it; see `examples/config.json`). Flags win over env vars, which win
over the config.

```json
{
  "vm": "ai-sandbox",
  "lima": "~/Developer/syd-guard/examples/lima/ai-sandbox.yaml",
  "localPorts": [5173],
  "env": { "GH_TOKEN": "file:~/.config/sydguard/secrets/github-agent-token" },
  "overlays": ["node_modules", ".venv", "target"]
}
```

`env` values are passed to every agent; `file:` values are read from files the
sandbox can't see. With a VM, the needed parts (resolved) are copied into the VM's
own protected config dir before each run.

## GitHub, CI and other services

Agents use their normal CLIs (`gh`, `git`, `circleci`, `curl`) through the proxy;
approve the hosts once. Give them **their own least-privilege credentials** via
`env`, not yours: e.g. a fine-grained GitHub token limited to specific repos with
contents/pull requests/issues read+write and actions read — enough to clone, commit,
push, comment, read comments and check GitHub Actions — and GitHub enforces the
limits even for `gh api`. `examples/config.json` also shows the `GIT_CONFIG_*`
entries that make `git push` use `gh`'s credential helper. Your own `~/.config/gh`
and `~/.ssh` stay unreadable to agents.

## Rules

`<git root>/.sydguard.json` (committable) or `--rules`, plus "all projects" rules
in `~/.config/sydguard/global.json` where the UI runs (mirrored to every VM):

```json
{
  "read":    ["~/.cache/go-build/**", "/opt/tool/*"],
  "write":   ["~/.npm/**"],
  "hosts":   ["https://github.com", "*.githubusercontent.com", "tcp://db.example.com:5432"],
  "connect": ["140.82.112.3!22"],
  "ignore":  ["telemetry.example.com"]
}
```

- **Built in** (shown in the UI): system dirs read-only; the project and `/tmp`
  read+write. `write` = read + create/modify/delete/rename.
- **hosts** are by name: `github.com` (any port/protocol), `https://github.com`
  (443), `http://x:8080`, `tcp://host:port`, `*.example.com` (subdomains only).
  They apply to the per-session HTTP(S) proxy *and* to tools that bypass it: the
  session's private DNS server only answers approved names and then allows the
  returned IPs on the rule's ports. Unapproved names don't resolve at all (no DNS
  leaks). Loopback/link-local destinations are never allowed by a host rule;
  private/LAN addresses need an exact `protocol://host[:port]` rule. HTTPS is
  decided by host and port, not URL path (no TLS interception).
- **connect** is raw IP/socket access (advanced); prefer hosts.
- **Protected**: the sandbox can't read `~/.config/sydguard`, sydguard's state,
  `~/.ssh`, `~/.gnupg`, `~/.lima`, and can't modify rules files, `.sydguard/`,
  `~/.local/bin`, shell rc files, `.git/hooks`, `.git/config`. Grants overlapping
  these are refused, and every live update re-applies the denies atomically.
- **Integrity**: only rules content sydguard wrote or you trusted is used. A file
  changed elsewhere (editor, `git pull`, clone, a hard link) is shown in the UI /
  terminal and ignored until trusted; files with extra hard links are refused.
- **Build folders stay in the VM**: `node_modules` next to every `package.json`,
  `.venv` (Python) and `target` (Rust) are bind-mounted from the VM's disk, so
  `npm install` and friends never write Linux binaries or install scripts' output
  into your host's project tree (the host sees an empty folder).

## How it works

- **With a VM**: `sydguard` prepares the VM and execs `sydguard` inside it. The UI
  server runs on the host, bound to loopback, and reaches each running VM's daemon
  over its Unix socket forwarded through Lima's SSH. VMs have no UI port. The UI needs no
  token: it refuses non-loopback Host headers (DNS rebinding) and any write that
  isn't a same-origin JSON request (cross-site pages).
- **VM daemon** (Unix socket, auto-started): compiles a Syd profile per session,
  runs its HTTP(S) proxy and DNS server, turns Syd's JSON denials (fd 3) into cards,
  and applies approvals/removals through Syd's IPC as one atomic `load` per
  session. Sessions show **applied / updating / unknown**; a failed or unanswered
  update is reported and stops further edits to that session — never shown as
  applied. Change events stream to the UI (SSE) so cards appear instantly.
- File accesses are denied immediately and succeed on retry once applied. Web
  requests and DNS lookups wait for your decision (10 min / a few seconds).
- Sessions use user+mount namespaces (private resolv.conf, overlays). Syd's IPC
  only accepts peers in its PID namespace, so live updates go through a short
  `nsenter` helper.

## Engine

Tested with upstream Syd 3.59 (the latest release), unmodified. `sydguard setup`
(automatic when sydguard prepares a VM) runs `internal/guest/install-syd.sh`: builds Syd 3.59.0
statically (`cargo --locked`, libseccomp 2.6.1 checked by SHA-256), installs it
root-owned at `/usr/local/libexec/sydguard/syd`, and adds an AppArmor profile that
lets only that binary create user namespaces (Ubuntu blocks this by default).
`sydguard doctor` checks engine, namespaces and daemon.

## Lima

- Built-in default (`internal/lima/default.yaml`): generic Ubuntu, `~/Developer`
  mounted at the same path, loopback ports forwarded to the host.
- `examples/lima/ai-sandbox.yaml`: a full AI workspace (Go, Node/pnpm/npm, Bun, uv,
  Playwright + browsers, Claude/Codex/Pi, linters, an `xdg-open` shim that prints
  URLs for OAuth logins). Personal extras go in `~/Developer/.sydguard-provision.sh`
  (see `examples/provision.sh`), which it runs if present.

## Development

```sh
make                       # web UI, Linux arm64/amd64 + host binary into bin/
scripts/check.sh [--fix]   # gofumpt, golangci-lint, go test -race, bun lint/fmt/check/test/build, shellcheck
scripts/e2e.sh             # inside the VM: real-Syd acceptance tests
```

Layout: `cmd/sydguard` (CLI, urfave/cli v3); `internal/policy` (rules, trust,
Syd profile); `internal/guest` (daemon, proxy, DNS, launcher, engine setup);
`internal/ui` (UI server + embedded build); `internal/lima` (running in Lima VMs);
`internal/api`, `internal/system` (shared). `web/` is Preact + vanilla-extract,
built by Bun into `internal/ui/dist`, which is committed (check.sh fails if stale).

## Known limits

- Landlock is off: approvals can extend anywhere (no kernel ceiling); Syd's
  seccomp path checks do the enforcing.
- If the agent kills the daemon, approvals, its proxy and DNS stop (fail closed)
  until it restarts and re-adopts the session. Syd itself keeps enforcing.
- Revoking can't undo completed I/O or close already-open files/connections.
- Compatibility switches are on for agents: TPE off, symlinks and file creation
  in group-writable dirs, W^X memory for JITs, non-PIE binaries.
- Programs on the UI's machine itself can use its API (like any local tool).
