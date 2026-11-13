# Temporary handoff — resumed integration checkpoint

## Operator-authorized remaining design calls — 2026-11-12

Operator explicitly said `do anything you want and anything that seems right` while
requesting all three remaining gates. Parent chose VM-local implementation/testing,
not host/account/audit changes or weakening confinement. Network requirement now uses
ROOT-ENFORCED FAIL-STOP if hostile tracee stops/kills its same-UID broker/supervisor;
ABI4 cannot claim blanket signal denial of those peers. Unconfined operator remains
trusted. Architecture reviewer6abcf accepted bounded immutable-helper/unprivileged-
broker source work under that explicit availability decision; no installed broker yet.
Source integration task active in fb76f4c5/task1; still no selected network activation.

Parent also authorized TEST CANDIDATE of unchanged upstream Syd3.59 source built
STATIC with panic=abort (build-option change, NOT the previously tested official static
binary and NOT an enforcement-source fork). Goal eliminate IPC worker unwind after
partial addressed-bank mutation by terminating entire engine. Separate ordinary VM
build/proof lane fb76f4c5/task2; no root engine replacement until review/identity and
fail-stop validation. Existing installed trusted engine/manifest remains unchanged.
Named-domain ordinary happy/error proof is retained, not enabled as full live safety.

Continuation status: network source has prebound constructors, journal/watchdog
resource phases, pidfd identity and finite ready/heartbeat frame primitives in retained
worktree a1a31df3; no real adapter/broker/ready release yet. Workflow242e091f reviews
that snapshot then continues real Linux adapter implementation. Main CLI remains
no-network and saved network intent rejected; do not deploy the partial source.

Abort build lane07413cb7 now has a linked STATIC NON-PIE aarch64 candidate using
unchanged Syd source, private Zig C23/native toolchain, musl and signed upstream
libseccomp2.6.1. This enables normal upstream libseccomp_v2_6 precomputation cfg and
is NOT binary-equivalent to earlier tested official stock engine. Root installation
remains untouched. Parent corrected overstrong no-unwind-symbol criterion: musl/std
backtrace support can retain _Unwind_* symbols; proof must establish actual Rust
panic entry routes to panic_abort/whole-process abort, not symbol absence.
Candidate now built/exercised but NOT QUALIFIED for root install: SHA523122c5dcc5f3b65b68b58fd642086d80aaa76c5c2e9825efc47b1750c69d01,
~/syd-abort-proof.lSrBGBxZ/bin/syd-3.59.0-abort, dev64769/inode1110172/mode0700.
New samePID258990 bank proof PASSED; process_vm_writev denial smoke PASSED after
honestly failed setup attempts. External process-directed SIGABRT was ignored,
consistent with upstream SigIgn/source; it is NOT an actual Rust worker-panic test.
Static actual panic path reaches musl abort; IPC default KillProcess filter should
kill process on abort's disallowed tkill. Independent reviewer in workflow8872d7ee
assesses this specific partial-bank hazard, held-writeguard/hook-stall implications,
static EXEC compatibility and dependency cfg. No Root replacement/enabling yet.
Network writer4d8e5d1 fixed stale durable journal and cross-netns ifindex findings,
but again did NOT complete real adapter: added FD/listener/netlink primitives only.
Fresh sole writer66165c64 in8872d7ee FAILED to implement adapter, no source edits.
Parent reported/stopped identical delegation and now owns retained a1a31df3 worktree
implementation. Anonymous netns FD leasing approved (no bind-marker namespace path);
watchdog verified lease ACK after durable record and before activation is mandatory.
Parent added actual nft GETTABLE handle parsing and atomic DELTABLE-by-handle code,
not deletion by name (Linux6.8 source explicitly prioritizes HANDLE); unit wire tests
and ALL helper tests executed ordinary UID502 Linux PASS. Still no full adapter or
selected launch activation. New dependency versions pinned in isolated worktree.

Reviewer59da22d8 accepted SPECIFIC partial-bank unwind gate conditionally: actual
panic-abort path plus IPC KillProcess filter; hook stall retains writeguard and blocks
new shared-policy readers, availability only. Explicit lock:ipc, reserved banks with
no automatic moves, prefix-safe compiler, single authenticated writer, unknown ACK
handling and exact abort-engine identity remain mandatory. Not installation/fullflow
approval. Parent independently rehashed candidate and ran existing ordinary-user
TestEngineStaticSydMetadataIntegration against it: PASS with UNCHANGED validator.
No runtime mutation/enabling or Root engine replacement occurred.

Latest source state (unmerged isolated worktrees):
- Bank compiler745ce315 adds internal/syd/live_bank.go/tests at4819fb2, explicit
  abort digest/startup banks/lock:ipc/typed inventory and exact receipt ledger.
  No launcher/IPC/UI/ceilings activated. Review217b4302 BLOCKED startup chdir/readlink
  missing, unknown ACK not quarantined and 108-byte socket grammar bound. Repair
  154b9e41 addressed all three + stronger source models; rereviewd2886d2d accepted
  repaired WORKTREE source, not older staged snapshots. Actual generated-batch
  ordinary candidate-only qualification ab558025 PASSED: engine261336/same shell
  PID261337, default deny -> generated fullA/fullB actual read/write/create/rename/
  unlink/lookup -> exact read-only A -> empty B revoke -> intentional failed prefix
  (155 genuine generated commands beforefinalmove) returnedEINVAL and defaultdeny;
  ledgerquarantined. dummy.env/.ssh chdir/readlink/privatecontrol read/connect denied
  everyphase with71KB engine denial evidence hash. LostACK separate modelonly.
  Fixture-only owned startup LLceiling, no production widening/auth/fullflow proof.
  Reviewed repaired compiler/tests + opt-in runtimefixture now applied main tree;
  parent native race/vet PASS. Handwritten prior fixture NOTcounted as compilerproof.
- Parent NFT review7f123c05 BLOCKED first transport: dependency FD0 sentinel,
  socket v0.5 callback swallowed creation errors, cancellation/origin correlation,
  malformed zero-length attributes. Parent replaced namespace dial with owned
  positive FD and disposable locked thread, raw bounded context-poll unix socket,
  real sender PID0 + exact headerPID/sequence and raw attribute framing checks.
  Codec/origin/cancel tests actual ordinary Linux PASS; reviewda8daf25 accepted these
  NFT source repairs, still requires real-kernel exchange tests. It BLOCKED route SDK:
  restore failure ignored/thread contamination, init FD ownership/finalizer bugs and
  percall timeout/cancel mismatch. Parent copied pristine vishvananda1.3.1 to local
  third_party/netlink (global cache untouched) and go.mod replace; narrow documented
  Go-library repair + owned/disposable/context-aware route wrapper active ed3e74c4/task1.
  This is NOT a Syd enforcement-source fork. Parent pauses network worktree writes
  while that sole repair writer runs. Repairfd2b420e completed owned/disposable
  current-namespace constructor, transaction-wide cancellation, safe private closed-
  socket retention/no fallback, init ownership fixes + PATCHES.md. Parent executed
  ordinary Linux ALL helper and selected safe nested SDK failure/finalizer/closed
  scope tests: PASS. Rereviewbb1040a7 accepted source repairs withP2 testdeadline
  weakness; parent fixedassert againstORIGINAL deadline+200ms (not1.5ssecondcall)
  andactualordinaryLinux testpassed3times at~1.0s. New library tests have NOT
  established real Root namespace/veth/kernel behavior.
- Parent network_links_linux.go now has real anonymous netns creation and DOWN
  veth creation across pinned namespace FDs, scoped index/MAC/peer verification and
  deletion by index. SOURCE ONLY; no privileged call exercised, firewall/activation/
  watchdog namespace ACK/broker/heartbeat/Syd/CLI still missing. Reviewed files are
  frozen during current read-only review. Neither source slice is ready to install.
- Parent ordinary helper test binary/temp owned fixture is recorded at guest
  ~/.sydguard-network-unpriv-parent-path; no Root/static-engine install there.


Unintended guest global rustup nightly install occurred during an intended read-only
`target list --toolchain nightly` probe. Worker stopped/reported, stable default is
unchanged. Retain identity for parent-reviewed cleanup: guest ~/.rustup/toolchains/
nightly-aarch64-unknown-linux-gnu, dev64769/inode1075650, owner briankemper, mode775,
rustc1.102.0-nightly3ef0c22cd, manifest2026-11-12. All subsequent toolchain work uses
private RUSTUP_HOME/CARGO_HOME under ~/syd-abort-proof.lSrBGBxZ (dev64769/inode1075506).
No automatic deletion or global toolchain/default/config change authorized for workers.
A GPG inspection also unexpectedly created guest ~/.gnupg dev64769/inode1110402,
mode0700, only pubring.kbx/random_seed, no imported keys; all later GPG uses private
GNUPGHOME. Parent informed operator and retains identities for reviewed cleanup.
Neither side effect is a successful isolation claim.

## Backend continuation after operator checkpoint — 2026-11-12

Operator explicitly requested all three backend gates and commit/push BEFORE work.
Verified clean f1141b2 already pushed to existing OPEN draft PR1. Operator's `ok`
in reply to the tracing question authorized the one bounded metadata-only VM trace.
No credentials/stdin/env/workload data captured; no audit changes. Existing root-owned
strace traced process/credential/prctl/exit metadata, with exec arguments raw pointers.
Verified helper/engine/policy hashes/dev/inodes and root stage identity first. Trace
original is root-controlled and identity recorded in installation.json; ordinary
copy fixture selected-metadata-only.trace. Child210544 killed immediately after
clone3 INTO_CGROUP and before any observed child syscall/UID change/exec; watchdog
cleanup after death. Trace did NOT identify signal sender or kernel cause.

Upstream6.8 source clears CGRP_KILL before kill write returns; persistent-poison
hypothesis not established. Retained writer resume failed because its empty managed
worktree had been auto-removed; stopped/reported, verified checkpoint clean, then
single retry in a fresh isolated worktree produced bounded diagnostic variant.
Fresh-group preflight now checks fixed cgroup interface metadata, exact domain and
populated0, opening cgroup.kill write-only WITHOUT an availability kill write.
Cleanup/watchdog/recovery still kill on shutdown and quarantine errors. Probe does
NOT prove future write availability. Independent review accepted source for narrow
diagnostic testing only. Linux full vet/race/lint/build passed after equivalent
De Morgan lint fix. NO enforcement engine/capability/mount/placement weakening.

Installed ONLY matching immutable disposable launch-helper candidate, after identity
checks. Old helper preserved root-controlled as launch_preflight_backup manifest entry.
Actual selected read-only/no-network launch PASSED exit0 PINNED_VISIBLE with exact
reviewed profile and dropped-capability checks; selected-nondestructive-preflight.log.
This is successful behavioral differential, NOT a proved kernel-level cause.
Slot reuse passed at /run/sydguard-launch/uid-502-slot-0.anchor/project.
First closed-stdio detached probe was inconclusive (/dev/full deny could prevent sleep).
Corrected fixture kept stdio and verified detached PID212448 ALIVE stateS in exact
session cgroup before foreground exit, then no longer running after exit0; evidence
selected-detached-alive-proof.log. No remaining anchor/cgroup children; intended slot0
file remains. Crash/cancel/mount flags/namespace replacement/stale CAS still need gates.
Saved writable source now integrated (common typed selected adapter, descriptor-relative
openat2 checks and conditional project RW bind, policy stays RO); unprivileged static
Syd file-operation tests passed and merged native/Linux full vet/race/build/lint passed.
Reviewer0655 initially found P1: relocated private-view paths can
hide original source-project overlap with trusted runtime exec hierarchies/whole home.
Source descriptor-identity/ancestry guard is now integrated and accepted after
additional mount-topology repair. Direct runtime overlap checks fixed verified root
FDs in both ancestry directions; UID home comes from root-controlled /etc/passwd,
not requested HOME. STATX_MNT_ID checks plus bounded /proc/thread-self/mountinfo
reject ANY other mount of the source filesystem, including descendant runtime/home
bind aliases. No topology path reopened as authority; unsupported layouts fail closed.
Failed reviewer provider502 followed unanswered supervisor question; recovered question,
reported failure, and same Pi review retried after operator explicitly resumed. Review
ad6e30c3 accepted scoped source fix; P2 ambient-topology test changed to getter-only.
Native/Linux full vet/race/lint passed including parser/mount tests.
Installed ONLY matching immutable writable launch helper after manifest identity/hash
check; previous readonly helper preserved as launch_readonly_backup manifest entry.
Actual fresh disjoint UID502 saved profile CAS/review/launch PASS exit0: create/edit,
rename/delete inside granted directory; editable no-delete unlink denied; readonly
write denied; outside/symlink-escape reads denied; both presented and private policy
mutation/chmod denied. Policy inode/bytes and readonly contents unchanged. Cleanup
no anchors/cgroup children, intended slot0 only. Evidence selected-writable-profile.log.
Actual RootOwner same-inode hardlink policy alias direct UID502 write/chmod denied;
aliased policy rejected before supervisor startup. Exact alias removed after checking
inode, original policy bytes/mode/inode/link count restored. Evidence
selected-policy-alias-rejection.log. This is not unmanaged-hardlink secret gate repair. Fresh disjoint writable fixture CAS
and manual review and workload proof recorded in pinned-writable-fixture.json.
Writable worker resume failed due auto-removed managed worktree (no further changes);
reported/stopped; WIP checkpoint then single fresh Pi-worker retry is planned.

Managed network half source integrated and reviewereb13 found no issues: exact
session/project/name/generation/start binding + snapshot revision/epoch receipt,
atomic profile-owned target replacement, no legacy-grant fallback for managed sessions,
old-epoch cancellation and locked final admission in both gateway/transparent paths.
Established admitted TCP connections may continue; future/pre-admission enforcement
only. Unit/mock broker positive/revoke/race tests passed, no real outbound traffic.
Not wired into selected Root network launch/controller yet; do NOT claim network
replay or persisted-live workflow done. Selected-network implementation worker halted
before inventing an unsafe root netns API: legacy controller resources lack authenticated
fixed-helper ready/FD handshake and persistent network-resource ownership. Concrete
report selected-network-integration-and-live-feasibility.task-1.md proposes an immutable
network-broker mode in the existing fixed helper, parent-owned socketpair/listener FDs,
root-generated bounded resource identities and typed ready receipt; architecture review
is active. No new broker/shim file/account/audit/root deployment occurred.

Novel unchanged-upstream live-file candidate: startup-predeclared default fallback and
bankA/bankB, one FD load moving to restrictive default, addressed inactive-bank rules,
then final atomic bank switch. Ordinary UID502 scratch proved SAME shell A -> default
on semantic error -> completedB real read/write (dummy.env denied) -> A deny again.
NO PRODUCTION ENABLEMENT. Addressed editing temporarily selects the bank; with_dom
restores default only on normal Result return, not RAII unwind. Follow-up confirmed
IPC is a separate syd_ipc worker; panic hook fatal behavior applies only MAIN, and
other workers recover poisoned Sandbox locks. Potential unwind/partial-bank hazard
is source-backed but no reachable valid-rule panic/exploit was observed. Do not call
happy/error proof unconditional live safety or assume worker panic aborts the process.
Reports upstream-domain-live-prefix-proof.md and .5ccabcd0.md, companion ordinary
repro artifact. All earlier in-place negative probes remain retained; none repeated.
Safe filesystem live mutation remains blocked; no unsafe recursive adds enabled.

After writable pass, actual cancellation also passed: workloadPID243758 alive in exact
session cgroup, CLI SIGTERM terminated it and cleaned anchor/cgroup; slot0 reused.
Evidence selected-writable-cancellation.log. This does not certify root-helper crash
or the not-yet-created network resources/lifecycle.

## Operator clarified acceptance contract — live persisted approvals

Every UI approval must persist corresponding public intent through authenticated
profile CAS AND apply it to the same running workload without process restart.
Profile-editor additions/removals must likewise save and apply; later launches
must enforce the same saved profile. Editing a registered project's saved profile
must work BEFORE any agent session starts; starting an agent to expose an editor
is not acceptable. Existing authenticated catalog is the pre-start discovery seam. UI must distinguish saved/applied/failure/
uncertain states, not call existing ephemeral live approvals this workflow.
Managed policy files remain UI/helper-writable only; ordinary project files are
editable by the operator outside the agent sandbox. Failed operations may need an
agent retry; previously read data/completed writes and held-FD/connection limits
must be stated honestly. THIS CONTRACT IS NOT IMPLEMENTED YET.

Real unprivileged upstream Syd probes confirmed same-shell-PID live rule addition
and removal, but separate recursive additions override the protected deny preset.
Follow-up found SCM_RIGHTS `load` parses multiple rules under one Sandbox write
lock: successful batches preserve final deny-last ordering. It does NOT rollback
on failure; a deliberately invalid later line left a recursive allow installed and
made the test `.env` readable. Do not enable naive batching or reappend-after-add
as live profile editing. Source task2 reports preserve these negative proofs.
Need a prefix-safe representation or separately reviewed all-workload quiescence
boundary (excluding Syd/IPC, otherwise freeze deadlocks). No such boundary has
been implemented or privileged-tested. Do not infer fork/new engine permission.

Private personal UI preview started on host localhost (separate new state/binary,
existing PID37288 default UI untouched). Host state/binary directory is recorded
in `/tmp/sydguard-personal-preview-path`; use its matching `ui ... status/stop`
and backend/guest flags, not default UI. Guest managed preview controller attempt
hit factory helper deadline and exited: current helper catalog takes ~2s per RPC,
so two-entry startup may exceed six-second total budget. Static UI returned 200,
profile API 502; link was given with explicit broken-profile-list caveat. Host
preview was rebuilt using Bun1.4.4 assets and latest Go CLI, and restarted to port
56655; use matching private UI status to obtain its operator URL. Frontend check,
lint and default tests passed (3 ordinary tests, 6 browser tests skipped). The
old TUN/explicit-proxy-only message is not the current App.tsx wording; veth and
synthetic DNS have an actual HTTPS learn proof, not full saved/live network replay. Guest
preview PID/identity recorded in fixture `personal-ui-controller.json` and log.
Pre-start provider repair now passes independent review and real private UI:
constructor validates catalog namespaces inside each of at most four concurrent
snapshot workers, cancels/joins on the first mismatch/error, preserves input order
and the original six-second total budget. Actual two authenticated helper reads:
serial4.03984s vsparallel2.04316s; fixture `parallel-helper-read-timing.json`.
Matching ordinary candidate CLI rebuilt; new private managed controller PID202461
is tracked in `personal-ui-controller.json`, no root helper replacement needed.
Host `/api/profiles` returned200/two profiles in4.121s, no active agents.
Real host Chromium then added an explicit read file rule and example.com TCP443,
saved/reread through installed helper CAS, removed both and saved/reread to restore
original logical intent. Evidence `/tmp/sydguard-prestart-ui-evidence.json` and
`/tmp/sydguard-prestart-preview.png`. Two initial browser script attempts sent NO
save: first omitted explicit read selection; second asserted Save immediately
while catalog refreshing. Final probe selected read and waited for readiness.
Catalog refresh still temporarily disables editing while each slow refresh runs;
record this usability limitation rather than claiming a nonblocking editor.
This is PRE-START SAVE/REMOVE proof, not live enforcement/replay. Root metadata-only
SIGKILL tracing was explicitly requested from operator and remains UNAPPROVED;
automated child notifications are not approval. Do not execute privileged tracing
or change audit settings pending an actual operator response.

## Reviewed JSON editor and stable polling preview — 2026-11-12

Integrated Form/JSON saved-profile modes and stable same-token background refresh.
JSON input rejects duplicate/unknown fields, lossy numeric tokens and unpaired
surrogates; raw-only edits participate in discard/unload protection. Save responses
must match binding, typed intent and exact SHA256 of the submitted cloned/minified
UTF8 profile bytes. Invalid/inconsistent/uncertain responses preserve drafts and
block blind retry. Operator bridge now validates/clones json.RawMessage instead
of remarshal: Go's default escaping had changed <>& and Unicode separators.
Managed helper profile payloads are base64 []byte, preserving exact bytes.
Added Go client_raw_test covering real client->controller->adapter byte preservation.

Polling keeps last successful same-token data usable while refresh is pending,
without making ceiling-ineligible grants available. HTTP401 latches both readiness
domains BEFORE parsing any error body; profile get/save/reload propagate captured
request-token auth failures. In-flight decisions remain guarded across token changes;
unknown outcomes require explicit fresh reconciliation, and absent pending request
is NOT proof an unknown operation failed. Run ACKs must match endpoint contracts.
Independent reviewers accepted repaired source; combined 29 browser/unit tests,
581 assertions passed with rebuilt production assets. Native/Linux Go vet,
uncached full race tests/build/lint passed. These remain UI/source gates, not live
persisted enforcement or saved-launch readiness.

Updated ONLY private guest managed controller, tracked PID209772 in fixture
personal-ui-controller.json. Updated ONLY separate host preview, now port59514;
obtain fresh URL/token with matching private ui status. Existing default PID37288
UI/controller was not altered. Real host Chromium JSON-mode save/read/restore via
Lima bridge and installed immutable helper passed for literal <>&, U2028/U2029 and
emoji. Original logical intent restored; Save stayed enabled during an actual slow
background catalog refresh. Evidence /tmp/sydguard-json-preview-evidence.json and
/tmp/sydguard-json-preview.png. No root helper replacement or privileged tracing.
Root SIGKILL trace approval is still pending an actual operator yes.

## User-requested UI demo (now ended) — 2026-11-12

Operator requested a live session and tokenized UI link. Started ONLY a disposable
normal transparent-run demo in guest fixture, not selected replay or permissive learn.
Demo CLI PID204083, session `9a34f701f2c1b89e5538855cf0ea87ee`, friendly label
`ui-activity-demo`, namespace `sg-863483`, project fixture `tmp/personal-demo-project`,
extra eligibility scope `tmp/personal-demo-inputs`. Workload `/usr/bin/timeout 600`
shell retries benign demo-file read and `https://www.example.com` every10s. The demo
self-stopped after its timeout; verified PID204083 and namespace sg-863483 absent.
Its completion RPC logged deadline exceeded, although resource cleanup completed.
Do not infer descendant containment proof.
Identity/started time in fixture `personal-demo-session.json`; logs
`personal-demo-session-fixed.log`. Real host Chromium verified running session,
www.example.comTCP443 pending, and file metadata denials; screenshot
`/tmp/sydguard-live-demo.png`. File denials observed were root/stat and inherited
output-log metadata outside the ceiling, not a proved actionable input-file prompt.
Saving approvals to a profile is unavailable for this unselected normal session;
do not claim this is the full workflow. Preview port56655, obtain fresh token using
matching private host `ui ... status` (tokensexpire30m; do not record token here).
Initial demo PID203916/netns sg-f2c657 used /dev/null redirection and thus did not
execute intended cat/curl. Stopped only identity-checked demo CLI; immediate netns
check raced asynchronous cleanup and halted restart. Later verified all original
CLI/sudo/supervisor/Syd/timeout/sh/sleep PIDs and namespace absent before new launch.
Original completion RPC hit deadline during signal cancellation; cleanup did complete.
No Root SIGKILL tracing was authorized by this request; that approval stays pending.

## Current WIP checkpoint — 2026-11-12 continuation

Operator requested a committed backup while work continues. **Not ready/green end-to-end.**

- Functional experimental `learn` source is integrated (risk consent required):
  no-network Go build succeeded after the operator explicitly approved upstream
  `trace/allow_unsafe_exec_nopie:1` for standard development toolchains. Added
  normal anonymous eventpoll/eventfd create grants; explicit `--require-pie`
  restores upstream non-PIE rejection and has real static-engine fixture proof.
  Compatibility does not disable file/network confinement or immutable-engine checks.
- Actual transparent learn curl HTTPS completed exit0, recorded exact
  `example.com/TCP/443`, and its veth/netns cleaned up (no test namespace left).
  Candidates are permission-check attempts, not filesystem-I/O success or complete
  coverage. Example records retained incomplete reasons, including cleanup timing.
- Learn private candidate/review/CAS/reconcile source and repairs are integrated:
  immutable envelope/counts/reasons, explicit incomplete consent, pending before CAS,
  known-not-submitted typing, atomic no-replace publication, output/SIGPIPE handling,
  guest-authority instructions and learning capability negotiation. Reviewer still
  found selected flags, publication-lock and historical hash-origin issues; repair
  child `da2ad303-55e7-44f5-8f91-45d894de2124` is now merged. Focused reviewer
  `865c3ec3-f877-4ab4-8701-99387571c5b3` found no introduced issues. Native and
  Linux full vet/uncached race/build/lint checks passed after merge. Historical
  learning hash matches map to manual/unknown and still require explicit current review.
- Saved replay source supports ONLY the first project-relative READ, no-network
  subset and explicitly rejects write/delete/network/external paths. Fresh ext4
  generation handles, exact expected revision/manual review, root-controlled private
  mount view, fixed immutable static engine, journaled UID slots, cgroup-v2/watchdog
  containment and safe nonrecursive recovery source are integrated. Learned lookup
  is wired under private review lock (initially held for whole workload, limitation).
- Fresh immutable matching policy helper/admin, launch helper and upstream static Syd
  were installed ONLY into the previously absent/verified disposable test-owned paths.
  Fixed runtime `/run/sydguard-launch` and dedicated cgroup-v2 root
  `/sys/fs/cgroup/sydguard-launch` were precreated and added to installation manifest.
  Fresh test-owned registry/enrollment replaced only the earlier test-owned registry.
- First ACTUAL pinned launch failed `invalid argument` (exit1), localized by added
  error context to the initial pinned-project FD bind. Namespace entry now precedes
  registry/handle/engine FD acquisition. Watchdog independently clones the already
  private namespace before binds, preserving an unmounted crash-recovery view;
  reviewer `f019f64c-341c-4880-8da6-f419e8bd965a` accepted source for disposable
  fixtures only. The matching immutable test helper was installed and identity recorded.
- Latest ACTUAL retry passed the earlier error stage but failed `sydguard launch:
  signal: killed` before supervisor announcement; no successful replay proof yet.
  Do not infer kill origin or complete mount proof from this message. Watchdog cleanup
  left only intended persistent empty UID502 slot0; no anchor/journal/cgroup children.
  Reviewed bounded stage/poll/elapsed-time diagnostics are now integrated and
  installed as matching immutable helper (manifest updated). P2 dispatch marker
  moved after unprivileged UID check. Native/Linux vet/race/lint passed. Actual
  diagnostic retry: supervisor PID199515 SIGKILL raw9 after ~888us; parent wait
  observed before watchdog socket readiness/kill (~0.3ms later), pidfd revents0.
  No supervisor entry marker. Outer fixture ~4.06s, 60s timeout did not expire.
  Watchdog cleanup successful; only intended slot0 remains. Filtered kernel log
  showed no PID/helper-name/SECCOMP-kill line. Do not infer kill origin yet.
  Evidence `pinned-launch-stage-diagnostics.log`. Privileged retries stopped.
  Evidence: fixture `pinned-launch-reviewed.log`, `pinned-fixture.json`, and report
  `pinned-launch-einval-diagnosis.f5831b7e.1f826671.md`. Preserve both launch and
  cleanup errors in the next diagnostic patch; watchdog-trigger/wait races can mask cause.
- Real candidate `b4d5f82cbc12667e4571a5b8f121e038` -> explicitly edited read-only
  intent -> matching installed immutable helper CAS -> authenticated reread PASSED.
  Review `44fb42fcdd5427792bfc26bb4c7af9ec`, project
  `3011ecc32b14606af5dcd72b4f140d629cabac428b01bf5e2956fbfbf67bb99b`;
  retained evidence `learn-real-save.json` and `learn-real-review.json`. This proves
  save, not replay, current learning origin, complete coverage or successful observed I/O.
- Attempted isolated diagnostic-worker launch failed because checkout was dirty; no
  child ran. Delegation stopped and failure reported. Checkpoint before a new launch;
  do not substitute external CLIs or treat the failed launch as completed diagnostics.
- Standard native full vet/race/build/lint and Linux full Go checks passed before
  this runtime failure. Two retained hardlink gates remain failing, unchanged.
- PIE toolchain investigation left a private ~971MiB copy under fixture/toolchains;
  not needed for default compatibility. A mistaken standalone env-filtered install
  created guest `go/bin/pieproof`; exact recorded test inode was removed, but default
  Go cache/telemetry may have been touched. No unidentified cache entries were pruned.
- Current actual installed binary/hash/inode state is in fixture `installation.json`;
  private native candidate UI/controllers were stopped or verified stopped before
  binary swap. Do not touch unrelated installed controllers or real projects.

## Live authorized disposable fixture — cleanup required

The operator explicitly authorized VM-local helper E2E and asked to finish learn/replay.
Only disposable `ai-sandbox` resources were installed; no real project migration,
old controller restart, account/sudoers/audit change or host helper action occurred.

- Guest ordinary UID: 502. Private source/build/test root:
  `/home/briankemper.guest/sydguard-helper-e2e.kFnn2q`.
- Dedicated immutable helper/admin were installed at fixed `/usr/local/libexec`
  paths only after verifying absent targets, root-owned nonwritable ancestors,
  copied hashes, UID0/mode0755/single-link. Fixed root registry is test-owned.
- `installation.json` under the private fixture root records current registry,
  binary and staging-directory device/inode/hash identities. CHECK these before
  privileged cleanup; do not delete/reuse a changed or real installation.
- Current candidate config: `/home/briankemper.guest/.sg-helper-test-kFnn2q`.
  Its managed credential is under `state/.sydguard-private/managed-credential`;
  never print/copy credential bytes into handoff, argv, UI or environment.
- Passing actual UID502 fixtures: installed helper catalog/CAS/namespace rejection,
  stalled input (20s)/cancellation, controlled static-Syd authority/FD test,
  two-project helper→controller→web API with real CAS conflicting writer, and
  root-owned canonical/preexisting-alias write/chmod denial. Unrestricted guest
  sudo is NOT RPC-only policy or cross-UID evidence; no configured sudo I/O
  logging/plugin override found in the checked config (auditing was not changed).
- Actual private managed CLI credential/enrollment/register/create/save/catalog
  and stale-CAS tests passed. Real Chromium via detached native UI and managed
  CLI controller/installed helper passed add/remove file/network intent and save
  reread; this does not apply permissions or prove replay. The temporary UI and
  tracked managed controller were explicitly stopped after this proof.
- Managed CLI/source committed as `dc69d21`; source has globally reserved private
  authority name and alternate-XDG real-Syd regression, plus post-commit reporting
  errors and SIGPIPE subprocess test. Deep fixture TMPDIR made an existing UI
  Unix socket test fail; ordinary default-temp rerun passed, no test disabled.
- Learning/replay initial children returned prerequisites only, NOT completion;
  parent rejected completion and resumed them for actual functional commands:
  learning `98259620-474f-4d4b-b6fd-dbe640ccbb82`, replay
  `b2386d63-66e4-464f-81e0-3dc8df9c462e`. Do not describe learn or --config as ready.
- Replay contract approved for CODE/REVIEW/disposable tests: fresh enrollment only,
  generation-bearing ext4 handles from held project/policy FDs, exact reviewed
  snapshot + private mount view/root-controlled sibling selected-intent anchor,
  post-drop bounded argv/FD handoff. Old/unpinned registrations/unsupported intent
  must fail closed. No real enrollment migration or broader deployment allowed.
- Learn must preserve full private candidate envelope/counts/incomplete/reasons and
  explicit reviewed edited intent, bind exact helper projectID/name/revision on CAS
  ack, persist pending before mutation and retain unknown on indeterminate result.
  No broad bootstrap grants persisted or fabricated successful-I/O/coverage claim.

## Resume progress (2026-11-12)

- Resumed on `feature/syd-guard-bootstrap` from clean checkpoint `44d14bb`.
- macOS Go vet/race/build/golangci-lint passed; native Bun lint/fmt/check/build
  and opt-in browser tests passed (6 tests / 111 assertions).
- Linux aggregate check now passes, including the previously unrerun learning
  fixture lint fixes. Guest browser tests remain skipped by default.
- Corrected `scripts/check.sh` to build embedded frontend assets before browser
  tests and Go consumers; reran the guest aggregate successfully.
- Explicit static Syd 3.59.0 unprivileged fixtures: learning permission-check
  candidate, strict `Run` and ordinary protected preset pass. Both retained
  preexisting-hardlink gates still fail (secret read and policy alias mutation).
  No failing gate was weakened or disabled.
- Applied the completed worker's managed-store protocol/client prerequisite patch
  to the local worktree: helper-returned registration/profile identity and namespace
  observations, strict nested parsing, exact replacement-byte checks and typed CAS
  conflicts. These are not namespace pinning or a production provider. Matching
  helper/client builds are required. Extended installed-helper tests were not run.
- Fresh aggregate macOS Go vet/race/build/lint and Linux aggregate checks pass after
  applying the patch; Linux managedstore/controller race tests also passed uncached.
- Original reviewer failed twice with provider server errors. After the operator
  asked to continue, a fresh review on the working backend completed (run
  `45d36baa-abb7-404d-91c9-23acf5609318`). Its P1 helper/client path mismatch is fixed
  via shared validation before registration/publication and stored lookup; tests
  cover tabs/Unicode controls and rejection before touching policy directories.
- Added an unactivated `internal/controller/managed_profiles.go` adapter. It accepts
  only an explicit bounded subset of registered refs authenticated by helper reads,
  derives stable opaque tuple IDs, binds returned namespace observations, retains
  exact bytes and maps CAS conflicts/indeterminate mutations. It never reopens a
  returned path. Tests use injected transport, not a real installed helper. Catalog
  duplicate IDs and metadata retargeting also now fail closed.
- Follow-up review `d330bfc9-e5b1-4eab-894f-58720857537d` found five issues;
  fixes validate original registration UTF-8 before marshaling, preserve uncertain
  save outcomes through API/bridge/editor, bound the complete catalog/save operation
  (6s helper work, 10s operator budget, 15s UI write timeout), permit long display
  paths and move shared errors to platform-neutral source. Browser regression covers
  typed/lost/legacy ambiguous saves, preserved drafts and explicit reconciliation.
- Review `d0f34b1e-bb86-4a3b-8499-90c416eade64` caught timeout spillover into live
  decisions, profile reaping lock waits and slow catalogs superseded by polling.
  Fixes scope new transport/browser budgets to profiles, check cancellation before
  queued network allow/deny commits, remove synchronous reaping from profile
  handlers, make candidate-lock acquisition context-aware and serialize refreshes.
  Tests cover these locks/cancellation seams and a 2.5s catalog response.
- Review `8c305264-4633-4198-9c00-732628c21b76` found single-flight live-status
  blocking and stale candidate visibility. Catalog and live status now have
  independent sequencing/lifecycles, read-only fetches are bounded, and candidate
  discovery checks current process-start identity without teardown. Tests recover
  approvals after a stalled first status read and reject exited/reused PIDs.
- Fresh macOS Go vet/uncached race/build/lint and Linux aggregate/touched uncached
  race checks pass. Native Bun/browser tests now pass 9 tests / 150 assertions.
  FreeBSD arm64 and Windows amd64 controller/managedstore package builds pass;
  this is compile evidence, not platform runtime support. Real-Syd suite recheck
  still fails only the two retained hardlink gates; files/learning packages pass.
  Application budgets are cooperative, not universal kernel/filesystem-hang bounds.
  Independent acceptance review `9c8309e3-3331-4d53-b883-2b7763064563` completed
  with no findings: OK for the bounded unactivated component only, not production
  deployment/catalog/replay. Reviewer did not run tests; parent ran the checks above.
- Reviewable commits: build order `a0168b0`, managed snapshot identities/path checks
  `6b10490`, bounded adapter/cancellation guards `6c737f3`, uncertain-save UI and
  independent polling `ae357cc`. Continue on the same feature branch/draft PR;
  no main merge or artifact promotion. Documentation checkpoint follows these.
- Continued from `2e65ba1` with a bounded authenticated helper catalog and
  `NewCatalogProfileProvider`. Catalog scans only caller-UID root registrations,
  validates profile bytes/revisions and directory identities, has explicit caps
  and fresh scan offsets, supports empty results and rejects partial/stale results.
  Empty registered projects have no profile entry. Factory authenticates the whole
  catalog before exact snapshot reads, rejects alias/namespace drift, and treats
  fresh revisions as current intent rather than reviewed/applied permissions.
- Worker `653139d6-0936-4148-9e97-cda8b0634311` completed isolated source; its patch
  is integrated. Review `cd6be25c-2cac-43bd-bb45-74dcfc722713` found four P2s;
  fixes cover restrictive umask on newly created locks, impossible namespace data,
  cross-registration aliases and filesystem-locality wording. Follow-up reviewer
  `9642e3bb-c055-4d0c-9464-8e485e868d29` reports no issues, OK unactivated only.
- Catalog/factory source committed as `9f9ea71` (helper/catalog) and `a2f9db4`
  (unactivated catalog-backed factory), followed by this documentation checkpoint.
- Current catalog/factory checks: full macOS vet/uncached race/build/lint, Linux
  aggregate and uncached managedstore/controller race checks, Linux enumeration/
  wire/umask regressions, FreeBSD/Windows package builds all pass. Browser source
  is unchanged from the prior 9-pass/150-assertion proof; guest browser tests skip.
- Extended the opt-in installed-helper fixture with catalog assertions but did
  NOT run it. Read-only probe found helper/admin paths and fixed registry absent.
  Folded public deployment gates into README; no helper installation, real policy
  enrollment, sudo/sudoers/account/audit change, active-controller restart or real
  project ownership migration occurred.
- Next: separately authorized disposable installed-helper E2E, protected caller
  configuration/production adapter hookup, and pinned namespace consumption before
  selected-profile runtime replay. Catalog source is not production activation.
  Known hardlink gates remain failing and unchanged.
- Retained initial worker patch/report: run `08551b8c-92c8-4608-8fa7-e894a55f7134`;
  failed reviewer retry: `cbe8e60f-012f-4abb-8b1f-e824046c335c`.

The original paused context below remains relevant until integration is complete.

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
