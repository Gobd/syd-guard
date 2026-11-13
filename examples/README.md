# Examples

- `config.json` — copy to `~/.config/sydguard/config.json` on the machine you run
  `sydguard` on. Default VM and Lima file, helper ports, env vars for agents
  (`file:` values are read from files the sandbox can't see), `keepOnVM` (build
  folders such as `node_modules`, `.venv`, `target` that stay on the VM disk instead
  of your project), and suggested **host commands** for agents: push `agent/*`
  branches, create/view/comment on PRs, PR checks, view/comment on issues, GitHub
  Actions runs and logs, CircleCI pipelines. They run on your machine with your
  normal `git`/`gh`/`circleci` logins (git hooks disabled); edit or drop any.
- `sydguard.json` — a project rules file (`.sydguard.json` in the folder you launch in).
- `AGENTS-snippet.md` — a few lines to paste into `AGENTS.md`/`CLAUDE.md` so agents
  know about `sydguard cmd`.
- `lima/ai-sandbox.yaml` — a full AI coding VM (Go, Node/pnpm, Bun, uv, Playwright,
  Claude/Codex/Pi, linters). Use with `--lima` or `"lima"` in the config.
- `provision.sh` — a personal provisioning hook for private tools; copy to
  `~/Developer/.sydguard-provision.sh`.
