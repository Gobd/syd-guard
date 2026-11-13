# Examples

- `config.json` — copy to `~/.config/sydguard/config.json` (on the machine you run
  `sydguard` on). Default VM and Lima file, helper ports, secrets passed to agents as
  env vars (`file:` values are read from files the sandbox can't see), and which build
  folders stay on the VM disk. The `GIT_CONFIG_*` entries make `git push` over HTTPS
  use `gh`'s credential helper with `GH_TOKEN`. Use a **fine-grained token** limited to
  the repos and permissions you want agents to have (e.g. contents, pull requests,
  issues read/write; actions read) — GitHub enforces those limits.
- `sydguard.json` — a project rules file (`<git root>/.sydguard.json`).
- `lima/ai-sandbox.yaml` — a full AI coding VM (Go, Node/pnpm, Bun, uv, Playwright,
  Claude/Codex/Pi, linters). Use with `--lima` or `"lima"` in the config.
- `provision.sh` — a personal provisioning hook for private tools; copy to
  `~/Developer/.sydguard-provision.sh`.
