# Syd Guard takeover plan

## 1. Goal and current truth

**Not ready for user testing.** Continue toward one runnable FILE-ONLY vertical slice before doing more networking work:

1. Learn a no-network workload and review/edit literal file intent.
2. Save the profile through authenticated CAS.
3. Launch under that saved profile.
4. Edit/save or approve/remove file permissions in the UI; apply to the **same running agent PID without restart**.
5. Stop cleanly, then relaunch to verify persistence. This final relaunch is a persistence test, NOT how live edits are applied.

The operator explicitly wants work to continue and permits reasonable design choices. They are frustrated by architecture/component progress without a working loop. Do not promise a date or call another collection of passing primitives ready. Personally demonstrate the actual loop before notifying them that it is ready.

Full original goal also includes exact-host networking and managed denial cards; networking is now deferred until the file-only loop works. No ephemeral grants, saved-only approvals represented as applied, or restart-based substitute.

## 2. Repository and ownership

- Main: `/Users/briankemper/Developer/syd-guard`
- Branch: `feature/syd-guard-bootstrap`
- Last reviewed/pushed implementation baseline before this handoff: `faa7651` — original-FD cgroup sealing barrier, durable quarantine.
- Draft PR: https://github.com/Gobd/syd-guard/pull/1
- No workers are known to be actively writing at this handoff; latest workflow and workers completed. Verify before assigning any writer.
- Preserve unrelated/uncommitted changes. Never merge obsolete whole files from an old worktree over main.

Main currently has:

- Modified `HANDOFF.md` (latest scope/decisions, but its front matter predates the last test failure).
- Modified `go.mod` and `go.sum`: direct networking dependencies now grouped as direct; local-replacement module checksums removed. Versions unchanged. Review current diff; do not blindly revert.
- NEW, untracked accepted fixture/validator files under `cmd/sydguard-launch-helper/`:
  - `live_cgroup_seal_root_fixture_linux_test.go`
  - `live_cgroup_seal_fixture_validator_linux_test.go`
- The main fixture includes **two latest diagnostic edits not yet independently reviewed**: inherit parent standard stdout/stderr for the controlled ROOT child, and include raw pidfd poll/revents in its liveness error. These do not activate production live launch.

Retained relevant worktrees:

| Path under `/Users/briankemper/Developer/worktrees/syd-guard/` | Purpose/status |
|---|---|
| `file-live-layout-source` | Base `faa7651`; actual constructor/backing creation/tmpfs-cover source + journal. BLOCK one P1 described below; unmerged. |
| `live-compose-source` | Base `74a03bb`; accepted barrier prerequisites already merged main; repaired fixture accepted. Its fixture still has OLD `/run` executable constant and lacks latest main diagnostics. Do not copy it over main again. |
| `managed-observation-source` | Base `74a03bb`; repaired observation primitives; not independently rereviewed or merged. |
| `live-startup-review` | Startup/gate/pins pieces already merged; obsolete as whole-file merge source. |
| `ui-live-source` | Controller/UI saved-versus-applied bridge already merged; no production Ready caller. |
| `live-root-source` | Old incomplete work; obsolete whole-file source. |

## 3. What genuinely works versus what is missing

Demonstrated separately:

- Real learning, candidate review, authenticated save/reread, and browser Form/JSON editing.
- Saved read-only and writable filesystem launches without networking.
- Candidate-engine live filesystem bank switches/revocations in the same process.
- Sealed memfd batch transport with strict engine ACK plus server EOF.
- Controller/UI bridge source and ordinary negative tests.

Still missing as an integrated product:

- Fixed contained mutator spawn and authenticated typed FD/frame handoff.
- Complete layout: executable aliases, guarded project bind, immutable regular profile bind, socket creation/takeover.
- Ordinary exec shim/group/capability/NNP/FD inventory and direct coordinator→Syd parentage.
- Actual Root-private Ready/Release/update service, CLI connection and trusted controller registration.
- Idle/death fail-stop and post-seal identity-bound cleanup/terminal retirement/slot release.
- Managed denial observation transport/cards and CAS→Applied integration.
- Full same-PID UI qualification.

`RegisterManagedRootReady` has no production caller. Public live launch remains disabled. Network-bearing selected snapshots remain unsupported/rejected. Do not turn either on early.

## 4. Immediate bounded fixes

### A. Fix the contained layout's one P1 before merging

Worktree: `file-live-layout-source`.

Implemented actual source:

- `live_contained_layout_linux.go`: Root-contained constructor, fixed exclusive backing creation (`socket-cover`, `scratch`, empty `profile`), actual private tmpfs cover.
- `live_layout_journal_linux.go`: separate bounded typed mutator journal.
- Corresponding tests.
- Small `live_cgroup_seal_linux.go` delta: legacy recovery rejects layout markers too.

Review finding: `publish` checks the original deadline before synchronous durable writing, but not after. The final `profile:created` or `socket-cover:mounted` publication may finish after expiry and still return success without poisoning the instance.

**Small fix:** check the same original monotonic budget after a successful write, before stage success. Do not renew time or attempt corrective cleanup. Add two deterministic tests where a successful final writer advances the fake clock to expiry. Require error + poisoned instance + retained quarantine marker, no retry/cleanup. Run ordinary tests/race/vet and independently rereview the fix. Do not confuse source acceptance with Root qualification.

### B. Diagnose the actual kernel fixture failure; do not claim it passed

Source confinement was accepted, then fixed executable-path relocation was accepted. Actual Root execution FAILED before readiness of a controlled child:

```
fixture case clone-wins quarantined; preserve
/sys/fs/cgroup/sydguard-live-seal-fixture/seal-344266-18c9ee833f4a3e1422deb37fcffa6938-clone-wins
if present: fixture child is not alive
```

Parent child stdout/stderr were `/dev/null` then, so the first early-child error was lost. Latest main diagnostics retain its standard log streams and print raw poll results; they have been compiled but NOT executed/staged. Review this narrow change before next privileged probe. Do not invent the cause or treat this as evidence against/for the kernel barrier yet.

Preserve failed owned entries/evidence. No broad/recursive cleanup or adoption of stale entries. Inspect exact current identities/population before any separately justified cleanup. A new source/test probe is not permission to rerun already completed qualification blindly.

## 5. Exact Root fixture evidence and staging

VM: `ai-sandbox`, Linux `6.8.0-147-generic`, ordinary UID502/GID1000.

Initial failed staging attempt: `/run` is `tmpfs rw,nosuid,nodev,noexec`. `/usr/bin/env` returned126/permission denied; the fixture DID NOT execute. No NOEXEC flag was weakened. Keep that evidence:

- `/run/sydguard-live-seal-fixture/root.log`
- `/run/sydguard-live-seal-fixture/provision.manifest`
- Old unexecuted `/run/sydguard-live-seal-fixture/fixture.test`, SHA `b8fe893b9c60071d5567f4cda0013757c15e70fc9f59b64b461fd4790050c82e`, dev27/ino9256, Root0500/nlink1.

Accepted corrected FIXED executable path:

`/usr/local/libexec/.sydguard-live-seal-fixture/fixture.test`

Actually provisioned/executed objects:

- Executable directory: dev64769/ino1337280, Root0/GID0/0700.
- Binary: dev64769/ino1337307, Root0/GID0/0500/nlink1, size9670438.
- Executed binary SHA: `162c2589b7bda59345efa90593d10d8d738e15b2fbcae8b54ace90c44f9dab02`.
- Run-stage directory: `/run/sydguard-live-seal-fixture`, dev27/ino9254, Root0700.
- Independent lock: `fixture.lock`, dev27/ino9255, Root0600/nlink1.
- Cgroup parent: `/sys/fs/cgroup/sydguard-live-seal-fixture`, dev31/ino25704, Root0700. Last observed nlink3 after the retained failed child entry; do not assume still empty.
- Root log: `/run/sydguard-live-seal-fixture/root-exec.log`.
- Manifest: `/run/sydguard-live-seal-fixture/exec-provision.manifest`.
- Self/PID1 cgroup namespace verified dev4/ino4026531835 (`0xeffffffb`) during parent preflight.

Ordinary guest scratch: `/tmp/sydguard-parent-seal.UUsRem`.

- `fixture.test`: old NOEXEC-path build.
- `fixture-exec.test`: corrected-path build used for actual Root failure.
- `ordinary.log`, `ordinary-exec.log`: 12 validators passed, Root fixture skipped.

Latest main diagnostic build ONLY on HOST:

- `/tmp/sydguard-parent-seal-diag.x6CymU/fixture.test`
- SHA `befd5c838626a343f28c5814d8eb2f6c1b7116239f2f70b91395121b7957f723`
- Path pointer `/tmp/sydguard-parent-seal-diag-path`.
- NOT copied to guest or Root staged/executed.

Any restaging must verify exact old object identities/hash, preserve prior failed binary/log/manifest, record a NEW immutable binary manifest, and respect exclusive fixed-parent ownership. Do not overwrite installed Syd/helpers, change global mounts, use an interpreter/quickboot to bypass NOEXEC, or silently adopt unknown objects.

Fixture scope is ONLY controlled kernel clone/removal orderings; it does NOT call production `liveSealBarrier` or prove journal cleanup/UI readiness. Successful kill/populated0 alone is NOT the dead barrier: exact original cgroup removal is needed to reject late clone into held oldFD.

## 6. Architecture constraints the next agent must preserve

- Syd source enforcement stays unchanged. No PTY/TUN/TLS MITM/enforcement fork, seal bypass, invented UID flags, or new ptrace capability.
- Syd, gate, workload, broker and ordinary shim remain unprivileged with required cap-empty/NNP/groups. Root fixture children are fixed controlled TEST programs, not agents.
- Root coordinator may use already-present normal Root privileges for metadata/hash reads of its own Root-derived Syd child; no tracing or proc/LSM/global capability changes. Actual `/proc/<Syd>/exe` access while dumpable0 still needs qualification.
- Stock installed engine is unwind and remains unchanged. Abort candidate is unchanged Syd3.59 source compiled panic=abort, NOT official stock prebuilt. Do not install/activate it without exact immutable manifest and parent qualification.
- Candidate guest path: `/home/briankemper.guest/syd-abort-proof.lSrBGBxZ/bin/syd-3.59.0-abort`; SHA `523122c5dcc5f3b65b68b58fd642086d80aaa76c5c2e9825efc47b1750c69d01`.
- Normal Go non-PIE workload compatibility is approved; `--require-pie` rejects it. Engine EXEC vs fixed gate/workload PIE are different requirements. Working Linux static-PIE gate uses existing external GCC linking `-static-pie`, not invalid `-ldflags=-d`.
- Syd seals/self-execs memfd: installed versus running inode equality is false. Keep installed FD and verify sealed runtime hash/four seals + Root-derived pidfd/start/boot/held identity.
- Socket object owner Root0 differs from ordinary server UID502. Immutable startup IPC writer UID/GID0. Take directory Root0700 BEFORE exact socket Root0600; gate held until takeover/pins/Ready.
- Startup profile is readonly regular fixed bind, NOT `-P /proc/self/fd/...`.
- Gate release exactly FD3; dedicated Syd log FD4. No broad passfd or Root authority leakage. Gate restores dumpable1 immediately before ordinary agent exec.
- Whole-project RWD maximum is an explicit trusted live opt-in, not a saved permission or implicit widening. Preserve source ancestry/mount topology, NOSUID/NODEV/NOEXEC, policy/engine guards.
- Root mutations after ARM must occur in a fixed helper atomically born with `UseCgroupFD`/`CLONE_INTO_CGROUP`, never an outside-CG late writer. Coordinator→ordinary Syd direct spawn uses the SAME continuously held original CG FD.
- Watch kill/drain then one identity-checked rmdir precedes resource deletion. EBUSY => bounded optional second kill + quarantine, no rmdir retry. Layout journal writer and Watch seal writer are separate. Post-seal reread required before cleanup.
- Existing production barrier intentionally NEVER sends clean `C` or releases slot; complete cleanup authority first.
- Startup ARM has ONE original10s timestamp/budget; updates5s. No renewal via heartbeat/status. Busy/stale/unauthed updates must not kill a healthy session.
- `liveStartupArm` owner/mutex is process-local/nonserializable. Layout bootstrap may hold an authenticated COPY of the original frame, not another owner, ARM/COMPLETE/renew authority.
- New layout bootstrap inputs require FUTURE authentic initial user/PID/cgroup namespace FD acquisition, Root-parent role-authenticated handoff and pre-cover Watch clone. `/proc/1` alone does not establish initial namespaces in nested PID NS. These prerequisites are absent, not proved by current constructor.
- Saved ≠ Applied: only exact genuine Root receipt establishes application. Unknown/malformed/lost ACK is sticky unknown; no retry/rollback/historical-byte reconciliation.
- Engine ACK stays exact `{"err":0,"msg":"ACK"}\n` PLUS server EOF; no CloseWrite weakening, ancillary-rights leaks, trailing bytes or parser ambiguity.
- Honest revocation limits: completed I/O, held file descriptors, admitted TCP, sampled exec identity, hardlink/alias issues and blocked kernel syscalls. Do not promise retroactive reversal or syscall cancellation.

## 7. Implement the missing vertical slice, not more unrelated prerequisites

After the immediate fixes, integrate in this order:

1. Finish executable/gate aliases, source-guarded project bind, regular immutable profile installation and directory-first socket takeover in the contained layout.
2. Implement fixed contained mutator entry/spawn plus bounded typed authenticated FD/frame handoff. Real syscalls and actual descriptor inventory; no mock-only completion. Retain original CG FD; prove authentic namespace pins.
3. Wire ordinary shim/Syd/gate spawn, same original ARM ticket, Root runtime hash/proc checks, Root-private managed service, Ready→Release→COMPLETE, controller trusted registration. Keep public default disabled until qualification.
4. Complete idle death/STOP fail-stop and Watch post-seal exact resource deletion, durable terminal handling/recovery/retirement. Unknown effects quarantine, never optimistic slot reuse.
5. Qualify same-PID UI save/add/remove and genuine Applied receipts with subsequent fresh opens. Then saved-rule relaunch and failure cases (lost ACK, stale CAS, caller expiry, daemon STOP/death, alias/protected-policy attempts, detached children).
6. Add managed denial cards from reviewed observation primitives. Observations are revision-unattributed denied requests/proposed intent, not bank-epoch evidence. Preserve persistent CAS→Root receipt for approval. Networking remains deferred.

Prefer one concrete writer/integration lane with narrow read-only reviews. Previous large tasks repeatedly returned partial journals instead of actual layout bodies. Do not count those as completed stages, repeatedly rerun their passing tests, or spawn more architecture lanes to avoid integration.

## 8. Observation repair pending review

Worktree `managed-observation-source`; report `c21eac92.../reports/managed-observation-drain-repair.md`.

Repair separates bounded lexical pipe ingestion from one bounded filesystem-validation worker, nonblocking32 candidate queue, owned `StartDrain(*os.File)`/End/Join/Stop, stalled-worker accounting, lifetime tombstones and necessary codec line bound. Review before merge. No actual launcher FD4 custody, event transport, controller/cards or activation exists. Never let filesystem normalization block Syd's log pipe; loss must be explicit.

## 9. Reports to read

Common prefix:

`/Users/briankemper/.pi/agent/sessions/--Users-briankemper-Developer-syd-guard--/subagent-artifacts/outputs/`

Essential suffixes:

- `bf06ce74-e494-407e-9bba-3371e85ffa88/reports/contained-mutator-cgroup-seal-design.md` — approved containment/barrier design.
- `ca53b698-31e2-4d38-93bb-b44899dd65d1/reports/ordinary-syd-root-writer-design-review.md` — startup security invariants.
- `6c2d0ad9-e8f8-48d2-b8b3-8ccc999eef70/reports/file-live-layout-creation-and-cover.md` — implemented source vs missing stages.
- `6ef7ddaf-f3bd-409b-abc7-e2e64b8da02f/reports/file-live-layout-and-fixture-path-review.task-1.md` — one P1 publication expiry BLOCK.
- `6ef7ddaf-f3bd-409b-abc7-e2e64b8da02f/reports/file-live-layout-and-fixture-path-review.task-2.md` — executable relocation accepted.
- `945decd7-410d-418b-90ab-f916d4795116/reports/live-seal-fixture-final-accounting.md` — six fixture repairs and provisioning contract.
- `7c8a0f2a-f4dc-4714-ac13-173b6c4b89d6/reports/live-seal-fixture-accounting-acceptance.md` — accepted source, NOT kernel pass.
- `c21eac92-eb07-4190-aba5-e583053e07d2/reports/managed-observation-drain-repair.md` — unreviewed repair.
- `f19796f5-c91d-4e84-aa70-3c13b395cb40/reports/controller-ui-bridge-repair-rereview.md` — bridge source acceptance, no production caller.

`HANDOFF.md` contains older evidence/history, `README.md`/`TODO.md` current general limitations. This plan supersedes stale current-status claims, not security constraints or original evidence.

## 10. Execution discipline

- Parent-controlled disposable `ai-sandbox` development/qualification is authorized. Workers: NO Root/sudo, privileged cgroup/ns/mount fixtures, tracing/debuggers, account/audit changes, deployment/install, agent sessions, commits/pushes or subagents. They may write privileged fixture CODE for review. Parent alone decides/provisions qualified privileged probes.
- Ordinary route: `limactl shell --workdir /tmp ai-sandbox bash -lc '...'`; verify UID !=0, fresh owned0700 scratch, no `/workspace` changes. Copy via `limactl copy --backend=scp` to fresh private path. Existing tools/private offline caches only; no installs/global changes.
- Do not touch default host controller PID37288 or installed stock engine/helpers. Credentials must never be printed or copied into reports.
- Native async completions wake parent; no sleep/poll/rerun completed probes. One writer per retained tree. Source acceptance does not authorize deployment or certify the full flow.
- Keep independently accepted checkpoints backed up to the draft branch/PR, with WIP limitations explicit. This handoff checkpoint includes the plan and current main-tree fixture WIP; blocked/unreviewed retained-worktree implementations remain local and unmerged.
- Deferred accidental guest nightly rustup and empty `.gnupg` side effects remain recorded; no automatic cleanup.
