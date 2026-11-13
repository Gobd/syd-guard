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
  --rules NAME|FILE   rules file; default ./.sydguard.json, NAME = ./.sydguard/NAME.json
                      (two agents in one folder can use different rules)
  --learn             allow everything; save what the command used into the rules file
  --local-port PORT   let the agent reach 127.0.0.1:PORT (a trusted helper you run outside)
  --vm NAME           run in this Lima VM ($SYDGUARD_VM, config, default ai-sandbox)
  --lima FILE         Lima file to create the VM from if missing ($SYDGUARD_LIMA, config, built in)
sydguard ui                       open the approvals UI (starts it if needed)
sydguard ui status|start|stop     the UI server only (agents keep running)
sydguard ui restart               restart the UI server and daemons with this build
sydguard vm                       a shell in the VM at this path, outside the sandbox
sydguard vm -- cmd [args]         run a command there (e.g. logins)
sydguard vm list                  VMs: running/stopped, agents, sydguard build
sydguard vm start [NAME]          start or create a VM; install sydguard + engine
sydguard vm stop [NAME...]        shut down VMs (all running by default; --force with agents)
sydguard status                   overview of all of the above
sydguard doctor | setup           check / install the pinned Syd engine
sydguard cmd ...                  (inside the sandbox) host commands, see below
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
  "keepOnVM": ["node_modules", ".venv", "target"]
}
```

`env` values are passed to every agent; `file:` values are read from files the
sandbox can't see. `keepOnVM` lists folders that live on the VM's own disk instead
of in your project folder (default `node_modules`, `.venv`, `target`): installs and
builds inside the VM never write Linux binaries or install-script output into the
host's copy of the project, which just sees an empty folder. With a VM, the needed parts (resolved) are copied into the VM's
own protected config dir before each run.

## Host commands (git push, PRs, CI status, …)

Some things need your credentials: pushing, opening PRs, commenting, checking CI.
Instead of giving agents tokens, define **commands** they may ask sydguard to run
**on the host** (outside the sandbox and the VM, in the project folder, with your
normal `git`/`gh`/`circleci` logins):

```json
"commands": {
  "push":      { "run": ["git", "push", "-u", "origin", "{branch}"], "args": { "branch": "agent/[A-Za-z0-9._/-]+" } },
  "pr-create": { "run": ["gh", "pr", "create", "--head", "{branch}", "--title", "{title}", "--body-file", "-"],
                 "args": { "branch": "agent/[A-Za-z0-9._/-]+", "title": "[^\\n]{1,200}" }, "stdin": true },
  "runs":      { "run": ["gh", "run", "list", "--limit", "20"], "mode": "allow" }
}
```

Inside the sandbox:

```sh
sydguard cmd --list                                   # what's available
sydguard cmd push branch=agent/fix-login              # run one
sydguard cmd pr-create branch=agent/fix-login title="Fix login" < body.md
sydguard cmd --propose --why "need issue labels" -- gh issue edit 12 --add-label bug
```

- **Where**: global commands in `~/.config/sydguard/config.json`; per-project ones in
  the rules file (`"commands"`, committable — approved once per definition on the
  host before they run). There are none by default; `examples/config.json` suggests a
  set (push `agent/*` branches, PR create/view/comment/checks, issues, Actions runs,
  CircleCI) and `examples/AGENTS-snippet.md` tells agents how to use them.
- **mode**: `"ask"` (default — a card shows the exact command, you click Run) or
  `"allow"` (runs right away).
- **Proposals** show up as cards: **Run once**, **Save as command** (edit the
  template, turn words into `{placeholders}` with a regex each, pick this project /
  all projects and ask / allow), or **Deny**.
- **Safety**: argv is fixed — the agent only fills `{placeholders}`, each matched
  against its regex as a whole; values can't start with `-` or contain newlines; no
  shell. git (directly or via `gh`) runs with hooks and fsmonitor disabled. The host
  checks every request itself, so a compromised VM can't make it run anything you
  haven't defined or approved. Beyond that, what you allow is up to you: a command
  like `pnpm run build` runs project code on your host.
- The `sydguard` binary inside the sandbox is just a client; it has no more power
  than any other program there.

You can still give agents their own scoped tokens via `env` (e.g. a fine-grained
`GH_TOKEN`) if you prefer them calling APIs directly.

## Rules

`.sydguard.json` in the folder you launch in (committable) or `--rules`, plus "all projects" rules
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

- **Built in** (shown in the UI): system dirs read-only; the folder you launched
  in and `/tmp` read+write. Nothing above it: launch at a repo's root if the agent
  should commit (`.git` must be inside; its hooks and config stay protected). `write` = read + create/modify/delete/rename.
- **hosts** are by name: `github.com` (any port/protocol),
  `https://github.com` (TLS on 443), `tcp://db.example.com:5432`,
  `udp://service.example.com:9000`, `*.example.com` (subdomains only).
  Each session has a private TUN and tun2socks/gVisor TCP/UDP stack, not an
  HTTP/SOCKS proxy. HTTPS on port 443 checks TLS SNI against the DNS identity
  (no domain fronting, TLS interception, or URL-path rules). Other ports use
  raw `tcp://` grants. Plain HTTP on port 80 also requires `tcp://host:80`:
  only its initial Host is inspected, not every request on a reused connection.
  Existing `http://` grants must be replaced with an explicit raw TCP grant.
  A/AAAA DNS answers are synthetic, local-only identities, stable across daemon
  restarts. Real DNS resolution happens only after approving the connection's
  host, protocol and port. An unapproved lookup never leaves the namespace;
  unrelated names sharing a CDN address do not share authorization.
  Loopback/link-local destinations are blocked except explicit `--local-port`
  helpers; private/LAN destinations need an exact host rule.
- **connect** grants literal IP access (advanced); prefer hosts. Use
  `tcp!93.184.216.34!443` or `udp!93.184.216.34!9000` to scope the protocol;
  legacy unprefixed IP/port rules permit both.
- **Protected**: the sandbox can't read `~/.config/sydguard`, sydguard's state,
  `~/.ssh`, `~/.gnupg`, `~/.lima`, and can't modify rules files, `.sydguard/`,
  `~/.local/bin`, shell rc files, `.git/hooks`, `.git/config`. Grants overlapping
  these are refused, and every live update re-applies the denies atomically.
- **Integrity**: only rules content sydguard wrote or you trusted is used. A file
  changed elsewhere (editor, `git pull`, clone, a hard link) is shown in the UI /
  terminal and ignored until trusted; files with extra hard links are refused.
- **Build folders stay in the VM** (`keepOnVM` in the config): `node_modules` next to every `package.json`,
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
  runs its gVisor transport and synthetic DNS resolver, turns Syd's JSON denials (fd 3) into cards,
  and applies approvals/removals through Syd's IPC as one atomic `load` per
  session. Sessions show **applied / updating / unknown**; a failed or unanswered
  update is reported and stops further edits to that session — never shown as
  applied. Change events stream to the UI (SSE) so cards appear instantly.
- File accesses are denied immediately and succeed on retry once applied.
  Network connections wait for approval (up to 10 minutes; application timeouts
  still apply). The Sessions view shows per-session flows, protocol, port,
  hostname/SNI, counters, and approvals for that session's shared rules file.
- A session-lived, unprivileged helper creates user+network namespaces and the
  TUN **before** starting Syd. Syd creates its inner user/mount namespaces
  (private resolv.conf, overlays), with no `unshare/net`. The helper keeps the
  TUN and local-listener descriptors and passes duplicates to the daemon over
  a private Unix socket. The agent inherits none of these descriptors.
- **Dev servers**: TCP ports the agent listens on (any address, port 1024+) are
  mirrored onto the VM's loopback, which Lima forwards to the host, so
  `localhost:3000` on your machine reaches the agent's server. A port already in
  use there is shown as not exposed in the UI. Inbound only: this never gives the
  agent new outbound access.
- Agents run as your own uid inside their namespaces (not root), with no Linux
  capabilities.
- The launcher restarts a crashed daemon even without Syd log activity. The
  owner reconnects and hands back the same TUN/listeners. Existing flows reset;
  new flows work with unchanged routes and cached DNS identities. Live Syd IPC
  updates enter the owner's user/net and Syd's PID namespaces.

## Engine

Tested with upstream Syd 3.59 (the latest release), unmodified. `sydguard setup`
(automatic when sydguard starts a VM) runs `internal/guest/install-syd.sh`: builds Syd 3.59.0
statically (`cargo --locked`, libseccomp 2.6.1 checked by SHA-256), installs it
root-owned at `/usr/local/libexec/sydguard/syd`, and adds an AppArmor profile that
lets the engine and root-owned `/usr/local/libexec/sydguard/net-helper` create
user namespaces (Ubuntu blocks this by default). Neither binary is setuid.
The helper must match the sydguard build: with a VM, sydguard reinstalls it
automatically after upgrades; on plain Linux/WSL run `sydguard setup` after upgrading.
`sydguard doctor` checks engine, helper version, namespaces and daemon.

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
python3 scripts/network-e2e.py /path/to/sydguard # Linux: real TLS, TCP/UDP, restart + live IPC
```

Layout: `cmd/sydguard` (CLI, urfave/cli v3); `internal/policy` (rules, trust,
Syd profile); `internal/guest` (daemon, TUN/gVisor, DNS, launcher, engine setup);
`internal/ui` (UI server + embedded build); `internal/lima` (running in Lima VMs);
`internal/api`, `internal/system` (shared). `web/` is Preact + vanilla-extract,
built by Bun into `internal/ui/dist`, which is committed (check.sh fails if stale).

## Known limits

- Landlock is off: approvals can extend anywhere (no kernel ceiling); Syd's
  seccomp path checks do the enforcing.
- While the daemon is down, network forwarding stops (fail closed). Syd keeps
  enforcing; the launcher automatically restarts the daemon. Active network
  flows and the bounded connection history do not survive a restart.
- Revoking network rules conservatively closes active flows. Revoking cannot
  undo completed I/O or close already-open files.
- Compatibility switches are on for agents: TPE off, symlinks and file creation
  in group-writable dirs, W^X memory for JITs, non-PIE binaries.
- Programs on the UI's machine itself can use its API (like any local tool).
