<!-- Paste into AGENTS.md / CLAUDE.md for projects you run under sydguard. -->
## Sandbox

You run inside sydguard. Files outside the project, network hosts and other
access may need approval; if something is denied, say what you need and retry
after it's approved instead of working around it.

For things that need the user's credentials (pushing, PRs, comments, CI status)
use the host commands:

- `sydguard cmd --list` shows the available commands and their arguments.
- `sydguard cmd NAME key=value ...` runs one (some read input from stdin, e.g.
  `sydguard cmd pr-create branch=agent/fix-login title="Fix login" < body.md`).
- `sydguard cmd --propose --why "reason" -- PROGRAM ARGS...` asks for a new one.

Work on branches named `agent/...`. Commits are normal local `git`.
