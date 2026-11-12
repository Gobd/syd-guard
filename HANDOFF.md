# Temporary handoff — resume here tomorrow

Paused at the operator's explicit request on 2026-11-12. **Do not assume this is ready.** This file is intentionally committed for continuity and can be deleted after resuming. The operator wants the current imperfect/WIP state backed up, not another late-night check/fix loop.

## Repository and checkpoint

- Work in `/Users/briankemper/Developer/syd-guard`, not the Claude repo.
- GitHub: https://github.com/Gobd/syd-guard
- Draft PR: https://github.com/Gobd/syd-guard/pull/1
- Branch: `feature/syd-guard-bootstrap`; continue here, do not merge main.
- `main` was seeded with empty commit `a1d0048` for the initial PR.
- Earlier feature commits: `dad8d1c` bootstrap, `826b91f` simple access/CLI cleanup, `c5ae92f` profile editor/candidate API.
- The final checkpoint commit includes this handoff and experimental components copied from the finished isolated lanes. Use `git log` for its hash. They are source backups, **not enabled production features**.
- All currently launched subagents finished. Do not restart overnight work. No real helper deployment, old installed controller/UI restart, or user-project ownership migration was performed.

## Operator's settled product decisions

1. Standalone OSS Go wrapper around **unmodified upstream Syd**, no enforcement fork/custom syscall engine/TUN/relay/TLS MITM/own PTY.
2. Simple public filesystem config: `read`, `write`, `delete`; compile Syd details internally. Read includes inspect/list/traverse; write includes create/modify/truncate/metadata; delete includes unlink/rmdir/rename/replace. Write can destroy contents even without delete; atomic-save editors may need delete.
3. Example: `examples/profiles/default.json`, public fields `version`, `name`, `files[{path,access,recursive}]`, `network[{host,port,transport}]`. Old `capabilities` is rejected. Exact hostname/port/transport, no persisted DNS IPs. Literal relative/tilde paths; no arbitrary glob/empty/root grants.
4. Desired `learn` is **permissive bootstrap**: allow supported nonprotected reads/writes and public network traffic while recording observed narrow candidates. Intended for `go install`, `go build`, `npm install`, then stop, review/edit config, run strict. No mandatory directory guessing. Never persist the broad learning permission itself.
5. Normal `run`: selected reviewed profile, live UI per-run approvals and explicit save-to-selected-profile. Restart/retry needs must be honest; immutable kernel ceilings cannot magically widen.
6. Known environment files (`.env`, `*.env`, `.env.*`), credential/key/browser locations, controller/helper/policy authority remain excluded. A denylist isn't a universal secret classifier. **Preexisting hardlink aliases bypass current pathname-only protections**; retain the failing regressions, no categorical safety claim.
7. Repo `.sydguard/default.json`, named profiles and nearest-folder discovery; agent-readable intent, agent mutation denied. Private tokens/state completely unreadable. Operator must be able to edit through managed CLI/UI, not an agent root privilege.
8. UI is shared across Linux/native, macOS/Lima and WSL/Linux, not Mac-only. TUI is deferred; leave it future TODO, do not implement now.
9. Remove legacy/user-facing low-level plumbing. `--network-proxy` removed; scope/read-input/exec-input/service remain hidden advanced caller inputs until the profile workflow replaces the ordinary need. Services are generic DNS labels and exact loopback TCP endpoints, not application-specific names.
10. README/TODO are the main documents. PLAN.md, SPIKE-NOTES.md, NETWORK-PLAN.md were consolidated/deleted. This temporary handoff is the explicit exception. Keep application-specific references out of production docs/code; external work can be tracked in TODO/handoff.
11. Generic Lima example: `examples/lima/ai-sandbox.yaml`; loopback-only VM dev forwards 1024–10000. It validates but fresh provisioning wasn't tested. It doesn't by itself publish a dev server from an isolated Syd namespace.
12. `internal/webui/assets` intentionally tracked for Go embed, clean Go-only builds/module installation. `web/src` is editable source. Rebuild with Bun **before** browser tests/Go builds; a stale-bundle test timeout was fixed by rebuilding, not by weakening tests.
13. Go 1.27, urfave/cli v3.14.0, standard method-aware net/http mux. React/TS/Bun/vanilla-extract, embedded assets. **Native Bun lint/fmt/check/test/build only**, no Biome/Prettier/Oxlint/standalone tsc/Vite fallback.

## External caller dream / ideal user workflow

The operator wants to `cd ~/Developer/my-project` and run **`lambdap --syd pi`**, starting Pi in that same project. Syd Guard should own as much generic machinery as possible: host cwd to selected Lima mount mapping, warm VM/backend/session selection, sandbox/config lifecycle, approvals, learning/replay, terminal/argv/exit handling. Lambdap should be a **very thin caller**, retaining only application-specific auth/setup. Don't scatter path mapping/sandbox orchestration into every caller. Keep this aspiration in handoff/TODO rather than coupling the standalone OSS project or generic Lima example to Lambdap.

An earlier authorized worker changed `/Users/briankemper/Developer/LIVEauctioneers/claude` for this integration. Preserve its unrelated dirty WIP; don't stage/publish that repo without separate instructions. It passes a typed transient named service for its guest-local auth proxy and rewrites workload URLs; the generic Syd service parser now supports such names without literal app references. Full runtime compatibility has not passed.

## What actually works / current primary code

- Normal confined transparent launcher, protected separate Syd FD logging, controller protocol 3, named concurrent sessions.
- Veth/netns/nftables/private resolver lifecycle, synthetic DNS + TCP gateway, exact approved synthetic endpoint IPC ACK before logical approval, per-run file approvals.
- Workers reported actual private candidate Syd file/network denial → Chromium approval → successful retry, session attribution/isolation and UI restart survival. Narrow evidence, not full audit.
- UI detach/status/restart/stop and embedded frontend.
- Simple access schema/compiler mapping, generic trusted services, canonical protected preset. Ordinary `.env`/nested/symlink deny fixtures pass; hardlink regressions fail.
- Profile UI editor/load/save/reload/conflict UX has mock browser proof.
- Real Go profile routes and bridge preserve typed 409/conflict errors and PUT bodies. Production catalog discovers nearest default only for active projects, labels **untrusted-candidate**, mutation capabilities false. Managed save has an injected-provider test seam; **no production provider installed, reload unsupported, no active session profile selection minted**.

## Experimental code checkpointed tonight — NOT activated

### Strict replay

`internal/syd/strict_profile.go`, Landlock gate, tests; `RunOptions.ResolvedProfile`, `StrictInputs`, `StrictIPC`, `OnStrictRuntimeCapabilities`; config revalidation/deep ownership helpers.

- Non-nil resolved profile selects strict compilation; nil keeps old baseline.
- Reject project/runtime-baseline overlap; kernel ABI >=3; deep-owned handoff; explicit separately authorized runtime/IPC additions; protected rules last.
- Static guest strict fixtures passed (ABI4). Known hardlink tests still fail.
- **CLI/controller do not load a selected managed profile or use this seam yet.** No network replay from saved intent yet. Need effective-policy metadata, authorization, exact helper snapshot consumption, namespace binding and real combined tests. Parent added a private indirect platform gate to satisfy Darwin staticcheck without weakening rejection.

### Learning collector

`internal/learning/collector.go`, `stream.go`, tests and Linux fixture.

- Upstream `warn/...` permits and logs permission **checks**, not actual successful I/O. A DAC-failed write can be recorded; missing lookups may not appear. No supported success-only audit found.
- Explicit `permission-check-candidate` envelope, bounded exact-path/coarse-op and exact public-dial dedupe, protected/runtime exclusion, incomplete/loss reasons, strict malformed/unknown/null rejection, whole-event rejection.
- `FinishOutcome` must receive nonzero exit/signal/cancel/scanner/delivery errors; `(nonzero,nil)` from Syd.Run is not success. `Stream` waits for log EOF/dial quiescence.
- **Syd.Run/gateway are not wired, no private candidate persistence/review/activation yet; learn still fails explicitly.** Rate-limit-disabled claim requires actual `log/rlimit_interval:0`. Never promote an incomplete candidate as complete or drop its envelope. Public dial callbacks must happen after vetted successful dial, not DNS; exclude private service branch and failed dials. No claim of complete coverage even without known loss.

### Managed storage

`internal/managedstore`, `cmd/sydguard-policy-helper`, `cmd/sydguard-policy-admin`.

- Dedicated immutable root-owned executables, separate administrator enrollment/RPC, root-private fixed registry, fresh root-owned policy inodes, private credential, strict bounded protocol/CAS, typed indeterminate outcome and authenticated reread reconciliation.
- Fresh root-private staging + renameat2 NOREPLACE: **same-filesystem ext4/tmpfs only**. Reject existing unmanaged folders and shared/virtiofs sources. No chowning preexisting aliases, arbitrary root writes or root agents.
- Root-owned data resists alias write/chmod, but operator-owned parent pathname can still be renamed. Consumer must use exact returned bytes and bind project namespace; never reopen a returned path as authority.
- Correct static Syd credential/helper/sudo/namespace and FD fixture passed; publication fault tests and deadline tests passed. No production managed provider/deployment enabled.
- **Darwin/host shares unsupported**. Guest-root ownership on virtiofs failed; host-root ownership requires separate administrator-assisted native test (host sudo -n unavailable). Do not silently substitute unprotected repo JSON/private-backed presentation and claim physical source mutation protection.
- Remaining prerequisites: coordinated in-flight rename/consumption races, real cross-UID sudo/RPC-only policy, sudo stdin/I/O logging review (token transport), invocation quota and kernel-hang bounds, crash/registry recovery, actual caller ptrace/proc/FD isolation. Do not globally change sudoers/accounts/auditing or install on real repos casually.
- Helper deployment guide remains in the source snapshot below; fold necessary public setup guidance into README/TODO after review, rather than add another root plan document.

## Tomorrow's order of work

1. Read this file, README, TODO; inspect HEAD/worktree and experimental packages. Do not call all ready.
2. Review/check the copied repair code and integration boundary. Fix any remaining introduced lint/compile findings, without disabling security linters or failing regression tests.
3. Connect a verified VM-local managed-store provider to profile catalog/save using registered opaque project IDs and exact authenticated helper-returned snapshots. No trust from folder discovery. Add selected `--config NAME`/default resolution and session profile ID/name/revision. Don't advertise edit/save/reload capability until real adapter works.
4. Connect strict replay through private supervisor handoff, derive safe ceilings from reviewed intent, protected-authority preset and explicit runtime inputs, fresh logical hostname bindings. No implicit workspace RW for a selected strict profile. Live additions separately authorized; removals/outside ceilings restart honestly.
5. Wire permissive recording mode to trusted Syd stream + post-public-dial callback and private candidate lifecycle. Show its candidate/attempt/coverage limitations, irreversible writes and exclusions. Explicit review/save only; no broad rules persisted.
6. Wire saved file/network decisions and operator edit/reload; CAS conflicts preserve dirty edits. UI current contract uses access arrays, path/target comes from authenticated pending ID, recursion only when directory metadata verified. Capability flags default false. Reload/session binding must resist stale same-name generations.
7. Real full CLI+UI+managed-helper/bootstrap/replay E2E with test-owned candidate config, 2+ sessions, Go/npm setup, wrong host/port/protocol, sensitive paths/aliases, FD/forgery/control access, UI restart, cleanup/cancellation.
8. Only after proof, discuss the precise host-admin test/deployment action for Mac-backed configs and give operator tested first-use commands/URL. No paid model calls or automatic promotion unless authorized. Keep committing/pushing separate reviewable changes to draft PR; don't merge main. Delete HANDOFF after consuming/updating its context.

## Validation at pause — do not misreport green

- Before copying experimental packages, actual UI/API checkpoint: Go vet/race/build/golangci 0 issues; native Bun lint/fmt/check/build; browser opt-in **6 pass / 111 assertions**, including editor mock conflict/reload and readonly untrusted candidate. Guest full check script passed; browser tests skipped there by default.
- After copied experimental packages: added `golang.org/x/sys v0.49.0` (required by helper), `go mod tidy`; Mac Go vet/race/build/lint passed after four introduced test/stub lint fixes.
- Last Linux aggregate after copy: Go race tests passed, but **8 introduced learning fixture errcheck/gosec findings stopped the script**. Parent added narrow justified test-only comments/close checks afterwards; **not rerun**, because operator explicitly asked to stop and accept imperfect state. Final checkpoint may still need Linux lint tomorrow.
- Full opt-in real-Syd suite is NOT clean: retained preexisting hardlink env-read and policy-write regressions are known failures. Never xfail/delete/disable to claim safety.
- Fresh Lima recipe validates; provisioning untested. Installed guest/main UI artifacts weren't promoted to current source.

## Environment / essential commands

- Lima instance `ai-sandbox`, Ubuntu24 arm64 kernel6.8, guest home `/home/briankemper.guest`, Developer mount `/workspace` plus host-path alias.
- **Use ONLY** `/home/briankemper.guest/.local/opt/syd-3.59.0-static/bin/syd`. The dynamic `.cargo/bin/syd` is known to segfault. A helper worker accidentally selected it; correct static baseline/new helper fixture both passed. Another EPERM was just missing 0700 test profile parent; no hardening weakened.
- Controller state is config `state/`, not group-writable `~/.local/state`. Existing installed controller protocol may still be 2; current source3. Do not silently kill/update active sessions; use private candidate state and explicit compatibility handling.
- Guest old Bun lacks native lint. Source env FIRST, THEN prepend candidate PATH:

```sh
cd /Users/briankemper/Developer/syd-guard
go vet ./... && go test -race ./... && go build ./... && golangci-lint run
(cd web && bun run lint && bun run fmt:check && bun run check && bun run build && SYDGUARD_BROWSER_TEST=1 bun test)
limactl shell --workdir /workspace/syd-guard ai-sandbox bash -lc \
 'source "$HOME/.config/ai-sandbox/env.sh"; export PATH="$HOME/.local/opt/sydguard-bun-candidate/bun-linux-aarch64:$PATH"; bash scripts/check.sh'
```

Mac ShellCheck is missing; guest aggregate runs it. No external frontend tool fallback. Embed build before Go/browser tests. Root helper integration requires reviewed disposable immutable installation and must run tests/workload as ordinary UID, never a root mutable Go test binary.

## Retained source/evidence for debugging (all principal code now checkpointed)

- Isolated repaired source: `/tmp/sydguard-profile-next.LLmScJ/{store,replay,record}`.
- UI source snapshot: `/tmp/sydguard-config-lanes.6iHLPI/ui`.
- Upstream recording fixture/findings: `/tmp/sydguard-config-lanes.6iHLPI/audit/recording-investigation/{fixture.sh,FINDINGS.md}`.
- Helper guide: `/tmp/sydguard-profile-next.LLmScJ/store/MANAGED_POLICY_HELPER.md`.
- Managed artifact outputs under `/Users/briankemper/.pi/agent/sessions/--Users-briankemper-Developer-LIVEauctioneers-claude--/subagent-artifacts/`:
  - `outputs/063e6310-659d-40c3-a2ae-12a2a32f803f/reports/simple-profile-config.md`
  - `outputs/9b6978a9-b726-409e-982b-7a17bcff5146/reports/profile-api-integration.md`
  - `outputs/e9a90af8-44b4-4466-8d77-9688542b416f/reports/managed-store-security-review.md`
  - `outputs/0ec6f052-0c24-431f-b763-2de3c0d09705/reports/managed-store-correct-static-gates.md`
  - `outputs/d99c8ca9-e473-43ad-b31f-f94047674834/reports/replay-recording-independent-review.md`
  - `da47166b-9e4f-48bb-8245-1e67545670d6_worker_output.md` (replay repairs)
  - `67ec7002-4043-4e5e-8ee1-04625a29111e_worker_output.md` (collector repairs)
- All current runs finished; no new child should be launched tonight. No operator/controller master tokens or UI pairing URL are included here.
