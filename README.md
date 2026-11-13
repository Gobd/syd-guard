# sydguard

Run an AI agent under unmodified upstream [Syd](https://gitlab.exherbo.org/sydbox/sydbox),
get a browser card for everything it isn't allowed to do, and approve/deny it.
Approvals and rule edits apply **live to the running agent** through Syd's IPC
socket, and are saved to the project's rules file.

```sh
make                       # builds bin/sydguard (+ Linux binaries it installs into Lima)
sydguard -- lambdap pi     # from any project dir under ~/Developer on the Mac
sydguard --learn -- pi     # permissive run that records suggestions to review
sydguard ui                # open the approvals UI
```

On macOS it uses Lima VM `ai-sandbox` (`--vm`, `$SYDGUARD_VM`), starts it if
stopped, creates it from `--lima FILE` (or a built-in default) if missing, copies
the matching Linux `sydguard` in, and runs the command in the same project path.
Inside Linux/WSL run `sydguard -- cmd` directly. A background daemon (auto-started,
`~/.local/state/sydguard/daemon.log`) serves the UI on `127.0.0.1:7878`.

## Rules

`<git root>/.sydguard.json` (committable) plus `~/.config/sydguard/global.json`:

```json
{
  "read":    ["~/.cache/go-build/**", "/opt/tool/*"],
  "write":   ["~/.npm/**"],
  "hosts":   ["github.com", "*.githubusercontent.com", "api.example.com:443"],
  "connect": ["140.82.112.3!22", "127.0.0.1!8080"],
  "ignore":  ["telemetry.example.com"]
}
```

- Always allowed: system dirs read-only, the project + `/tmp` read-write.
- `write` includes create/delete/rename. `hosts` go through the per-session
  HTTP(S) proxy (domain level; HTTPS paths aren't visible without TLS interception).
  `connect` is raw Syd network for tools that ignore `HTTPS_PROXY`.
  `ignore` = deny without asking.
- The agent can never write the rules files, `~/.config/sydguard`, the daemon
  state/token, `~/.ssh`, shell rc files, `~/.local/bin`, `.git/hooks`,
  `.git/config`. These denies are re-applied after every live change (Syd's last
  matching rule wins).
- If the project file changes outside sydguard (editor, `git pull`, cloned repo),
  `sydguard` shows it and asks you to trust it before launching.

## How it works

`run` asks the daemon for a session → daemon compiles a Syd profile and starts a
proxy on a private port → `syd -P profile -- cmd`, with Syd's JSON access log on
fd 3 forwarded to the daemon as cards. Syd only lets the agent connect to its
proxy port (no DNS, no direct egress). Approve = save rule + `allow/...+pattern`
over IPC; delete = save + `allow/...-pattern`. Web requests wait for your decision
(up to 10 min); file accesses are denied immediately and succeed on retry.

## Not protected against

The agent killing the daemon (approvals stop; nothing opens up), Node versions
without `NODE_USE_ENV_PROXY` support, tools that don't use proxy env vars (they
fail closed and show up as `connect` cards).
