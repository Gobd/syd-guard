<!-- Paste into AGENTS.md / CLAUDE.md for projects you run under sydguard. -->
## Sandbox (sydguard)

You run inside a sandbox. Anything not yet allowed is denied and shown to the user
as an approval card; once they approve, the same action works.

What a denial looks like:

- Files: `Permission denied` (or "No such file") for reads/writes outside what's allowed.
- Network: a connection to a host that isn't approved yet waits for the user's
  decision; if they deny it (or it times out), it fails or is reset.

What to do: say exactly what you need and why (the path, host or command), then
**retry after the user approves**. Don't work around a denial (other paths, other
hosts, copying files, disabling checks) — the user decides.

What you can write: only the folder you were started in (plus `/tmp`). Your
sandbox rules file (`.sydguard.json`, `.sydguard/`) and `.git/hooks`, `.git/config`
are read-only to you.

Build/dependency output: host project files may be shared writable. Configured
build-folder names are denied until backed by a verified overlay. A first access
can fail while sydguard automatically prepares it; **retry the operation**.
`target` needs a neighboring `Cargo.toml` for automatic preparation. You can also
prepare a folder explicitly before installing (even without a manifest):

```sh
sydguard overlay add ./node_modules   # before npm/pnpm/bun install
sydguard overlay add ./.venv          # before creating the Python environment
sydguard overlay add ./target         # before cargo build
```

Wait for success before installing. If preparation fails, ask the user; they can
click **Create overlay** on the UI card. Do not choose another directory or a
symlink to bypass it. A recursive write grant is required, and the folder name
must be enabled in `keepOnVM`. Existing contents become hidden, not migrated.
Mounted folders and their ancestors cannot be renamed/deleted by this session.
This protects configured output directories, not arbitrary host files elsewhere:
install scripts still run with the project's other approved write permissions.

Network: use normal tools; nothing needs configuring. Every connection is
checked by host name, protocol and port. Servers you start (e.g. a dev server on
port 3000) are reachable by the user at `localhost:3000`.

Things that need the user's credentials — pushing, PRs, comments, CI status — go
through host commands (they run on the user's machine with their logins):

- `sydguard cmd --list` shows the available commands and their arguments.
- `sydguard cmd NAME key=value ...` runs one (some read input from stdin, e.g.
  `sydguard cmd pr-create branch=agent/fix-login title="Fix login" < body.md`).
- `sydguard cmd --propose --why "reason" -- PROGRAM ARGS...` asks for a new one.
  It may be run once or saved by the user; if denied, ask instead of retrying.

Work on branches named `agent/...`; commit with normal local `git`.
