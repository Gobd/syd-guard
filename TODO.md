# Syd Guard implementation status

Code is tracked on the bootstrap branch; a draft PR exists.
Checked items are verified milestones, not a security certification.

## Current usable checkpoint

Experimental default transparent foreground launch now uses the explicit tested
Syd 3.59.0 and a session-owned namespace. Private protocol-3 guest fixtures have
proved an actual HTTPS and file denial, Mac browser approval and successful retry,
and UI restart without stopping the agent. Immutable no-network remains an explicit
opt-out. This is not yet a complete model-ready or audited product.
README.md contains current commands, security boundaries and build provenance.
This checklist captures remaining work; don't infer full readiness from partial fixtures.

## Foundation / checks

- [x] Preserve paused Greywall/Greyproxy/Claude WIP with handoff files.
- [x] Go 1.27 module; urfave/cli v3.14.0; visible source/builds in this folder.
- [x] Native Linux / optional Lima backend selection; Mac auto-selects Lima;
      Windows uses the Linux CLI inside current WSL.
- [x] Validate instance names; preserve argv without shell interpolation.
- [x] Help/version/initial doctor, private operator config path/show.
- [x] Lima recipe path/show/set/edit in source; file hash/drift reporting.
- [x] Config load/save privacy, owner/mode/symlink/unknown-field/trailing-data tests.
- [x] Go profile compiler: canonical literal paths, injection/broad-root rejection,
      separate filesystem-kind/path/Landlock layers, hard-protected paths.
- [x] Race tests, vet, builds, gofumpt and golangci-lint pass (standard + gosec,
      gocritic, misspell, unconvert, nolintlint).
- [x] scripts/check.sh includes ShellCheck and reports absent frontend as skipped.
- [x] Latest Mac/Linux ARM64 CLI builds copied/tested in the VM.
- [ ] Config CLI editor failure/drift/end-to-end tests and safe concurrent changes.
- [ ] Uniform config-location behavior/secure ancestor checks.

## Upstream installation and reproduction

- [x] Pin/test upstream Syd 3.59.0, no private fork/source patches.
- [x] Diagnose libseccomp 2.5.5 link failure; build upstream 2.6.1 user-locally.
- [x] Record source URLs, official binary/signature/key hashes and exact verification
      method in README.md (Signify Ed25519, not OpenPGP).
- [x] Verify/compare official static ARM64 3.53.0 without making it the default.
- [x] Find public dev/release.sh recipe: static libseccomp + crt-static.
- [x] Build latest tested 3.59.0 statically; default-hardening runtime works.
- [x] scripts/install-upstream-syd.sh resolves stable releases or explicit version
      overrides, verifies libseccomp checksum and installs a separate candidate.
- [x] scripts/integration.sh repeats real default-hardening tests in Linux.
- [ ] Exercise release-discovery network paths and clean-install prerequisites;
      latest-version selection is code, not proof every future release works.
- [ ] Engine selection/promotion/version-capability workflow; no implicit upgrade.
- [ ] Evaluate whether any narrow AppArmor setup is actually needed for the final
      supported build; global AppArmor was not disabled.

## Immutable runtime tests

- [x] Default-hardening 3.59.0 private-profile fixture allows a workdir write.
- [x] Outside write and authority read/profile-write attempts are denied.
- [x] Nested exec'd child cannot write outside the workdir.
- [x] Virtual /dev/syd permission edit attempt is denied.
- [x] Connection to a live local TCP test server is denied with no grants.
- [x] Go immutable launcher works in guest and through Mac/Lima adapter.
- [ ] Detached/reparented descendant fixtures.
- [ ] Broker termination/failure must remain fail-closed.
- [ ] Inherited FDs, proc magic links, hardlinks/symlink/rename alias attacks.
- [x] Bounded protected-name preset and file-approval rejection, with real 3.59.0
      nested env-name, selected credential directory, symlink and new-hardlink tests.
- [ ] Full read/write/create/delete/rename/truncate preset matrix and inode-level
      protection against preexisting secret hardlink aliases; the real
      TestProtectedPresetPreexistingHardlinkIntegration gate currently fails.
- [ ] More protected-path overlap tests and directory-owner checks.
- [ ] Interactive harness/TTY/signal/exit behavior; no custom PTY/browser terminal.
- [ ] Native Claude/Codex/Pi/build/Playwright compatibility inside this baseline.

## Mutable controller / learning (partial)

- [ ] One Linux controller with private authenticated operator API and typed Syd IPC.
- [x] Runtime fixture: lock:ipc blocks workload socket/virtual-API access; a trusted
      Go client adds a live read grant within a predefined Landlock ceiling, while
      write remains denied. Typed API/version/ACK handling is implemented.
- [ ] Extend that boundary to inherited FDs, proc aliases, separate UID/peer-cred
      cases, revocation and controller failure; fixture is not a full audit.
- [ ] Separate trusted Syd event source; do not trust arbitrary agent stderr.
- [ ] Live changes vs immutable outer ceiling/restart-required behavior.
- [ ] Implement opt-in permissive `learn` discovery/recording of actual supported
      reads and writes under honest immutable ceilings; record only observed narrow
      rules, deny known secret/control/key paths and protect against aliases. Real
      writes cannot be undone; known-secret lists are not universal. The current
      denial/review workflow is not discovery, and no finalized profile is produced.
      Supported public network access should also be allowed and recorded narrowly
      during bootstrap, excluding protected targets; this remains unimplemented.
      Current network requests still require approval. No broad learning rules may be saved.
- [ ] Make `learn` usable without mandatory `--scope`: predeclare sensible
      tool/cache learning ceilings without granting access automatically, and show
      outside-ceiling denials as restart/ceiling-review required rather than hiding
      them. Keep `--scope` as an advanced additional ceiling override. For Go,
      safely resolve the user's actual GOMODCACHE, GOCACHE and selected GOBIN or
      GOPATH bin paths and make those paths eligible for read/write review; network
      approvals remain exact and separate. Replay explicit saved approvals from the
      selected profile. Do not grant the whole home, auto-grant access, disable
      Landlock or overlap protected controller authority.
- [ ] Upstream Pandora/trace import, trusted learning candidate review and retention.
- [x] Named repo profile create/discover/show/trust commands and hash-review tests:
      nearest ancestor .sydguard/default.json or NAME.json; new profiles start empty,
      discovered/changed permission files aren't automatically trusted.
- [ ] Wire run/learn --config NAME, saved file/network decisions and fresh launch
      replay into selected repo profiles; no stale DNS-derived IPs persisted.
- [ ] Prove agent-readable project configs deny write/delete/rename/replacement,
      directory ancestor and hardlink/proc aliases. Private tokens/state stay unreadable.
      **Confirmed blocker:** real Syd 3.59.0 path denies do not prevent mutation of
      a profile via a preexisting hardlink in the writable workspace. The opt-in
      TestReadableProjectPolicyMutationDeniedIntegration fails on this bypass.
      A test-owned private mount namespace confirms a read-only bind over the
      canonical path does not protect the backing inode through a writable alias;
      design and verify a stronger boundary
      and private reviewed snapshot before wiring project profiles into launches.
      A test-owned root-owned 0644 file and 0755 policy directory blocked a
      writable hardlink alias with an unprivileged Syd workload. This is only a
      prototype: safe adoption of single-link inodes, managed saves, parent/alias
      races, privilege boundaries and review/conflict semantics remain unproven.
- [ ] Config validation/canonicalization, trusted snapshot/atomic UI save conflicts,
      relative/tilde paths, profile switching and read-only mount diagnostics.
- [ ] Explicit export/trust workflow; preserve reviewed denies.
- [ ] Exact once semantics only on backends that can enforce them atomically.
- [ ] Correct retry-required/hold/resume status and bounded pending requests.

## Sessions / Lima

- [x] Registry package: opaque run IDs, basename/-1/-2 atomic names, defensive
      views, history/name release and stale-identity rejection; 50 concurrent-name
      tests pass. Registry is wired into foreground launches and a Linux daemon;
      three concurrent real runs receive distinct labels and completion history.
- [x] Linux process boot/start-tick identity and authenticated native ServeMux API
      foundation; unknown/self-asserted inputs and false finishes are rejected.
- [x] Registry retains at most 256 ended summaries without discarding active
      sessions; race-enabled tests verify the bound and active-ID preservation.
- [x] run auto-starts/reuses the protected Linux Unix-socket controller; sessions
      lists active/history via native or Mac/Lima delegation. Private token is
      atomically published; a lifetime lock prevents competing controllers.
- [x] Real workload cannot read controller token or connect to its socket; dedicated
      scripts/session-smoke.sh verifies that and concurrent labels/completion.
- [ ] Durable registry recovery and daemon stop/restart CLI. Current entries track
      foreground supervisors, not proven whole descendant lifetimes.
- [ ] Foreground + optional tmux persistence/attach; no terminal server of our own.
- [ ] Status/stop/restart, stale PID protection, recovery and bounded audit history.
- [ ] Restart refuses active sessions unless explicit safe operation is chosen.
- [ ] Default/override Lima config, managed instance fingerprint/adoption/drift.
- [ ] Serialized auto-start/provisioning for run/learn; --fresh-vm without disrupting
      running instances; host/guest path mapping and mount ceilings.
- [ ] Doctor/provisioning for latest tested native harnesses and supported engine.

## Network / UI (partial implementation; full workflow not ready)

- [ ] Primary transparent DNS/synthetic-address network path: ordinary clients
      require no proxy-env cooperation; logical hostname + actual port + transport
      remain tied together. README.md records the acceptance criteria.
- [x] Disposable Linux veth/netns/nftables redirect fixture passes in Lima:
      synthetic TCP + controlled TCP DNS reach test listeners; direct real-IP and
      host-service connections fail, even with proxy env bypassed.
- [ ] Wire production session-owned veth/netns/nftables path into run/learn;
      bounded privileged setup outside agent authority. No TUN/relay daemon.
- [ ] Add source-scoped DNS listeners, namespace resource collision/recovery tests,
      original-destination checks, and firewall-before-activation/failure fixtures.
      Redirect-only listener ingress and exclusive nft table collision rejection now
      pass disposable guest fixtures; transit-address collision and production
      lifecycle/cleanup ownership remain unproven.
- [x] Session-local synthetic mapping + vetted DNS parser tests: canonical names
      have stable addresses, distinct names don't share synthetic identities,
      DNS alone creates no port/protocol grant; unsupported AAAA returns no data.
- [x] Transparent veth TCP fixture recovers original destination and records exact
      example.com/TCP/443; initial request denied, operator approval then real HTTPS
      retry succeeds with proxy cooperation explicitly disabled.
- [x] Private protocol-3 CLI + namespace + Syd trusted logging/IPC fixture: real
      Mac Chromium browser approves actual HTTPS and file denials; retries succeed;
      UI restart leaves the fixture agent running. This does not prove full coverage.
- [ ] Production controller/CLI/Syd live-grant + resolver configuration audit;
      latest transparent fixture is not a complete Syd session workflow. A separate
      guest Syd fixture verifies a trusted TCP connect-denial record and successful
      exact live IPC grant/retry with a 1-65535 Landlock port ceiling; it uses a
      test-local loopback listener, not the production synthetic gateway. The typed
      synthetic IPv4/TCP grant and denial parser remain unwired to the controller.
      Guest unprivileged user/mount namespace setup fails (uid_map EPERM / Syd
      EACCES), and sudo -C is disallowed. Approved direction: exclusive validated
      /etc/netns/<session>/resolv.conf lifecycle and an unprivileged supervisor
      inside the netns to create the trusted log pipe after setpriv. Neither is
      implemented or independently security-reviewed yet; no global DNS changes.
- [ ] Immutable port ceilings, rebinding defenses, IPv6/UDP support and fail-closed
      behavior on component termination, cleanup ownership/collision audits.
- [ ] Audit the generic trusted named service route: a single validated DNS-label
      name maps only its exact `<name>.sydguard.internal` TCP port to a declared
      loopback endpoint. Cross-repository callers need coordinated URL changes.
- [ ] Explicit HTTP/CONNECT proxy is an exploratory alternate adapter only; source
      exists, but real Syd egress integration and lifecycle audits are not complete.
- [ ] Exact host+port+transport; no port inferred from DNS alone.
- [ ] Vetted DNS parsing, A/AAAA/CNAME/TTL/refcounts/session scoping/rebinding guards.
- [ ] Protected resolver/control endpoints and narrow port-53 activation mechanism.
- [x] Authenticated native ServeMux APIs for file/network pending requests and
      decisions; web bridge exposes only approval/read routes, not raw Syd IPC.
- [ ] Optional future TUI; deferred, no implementation planned for this stage.
- [x] React/TypeScript/Bun/vanilla-extract approvals UI built and embedded; local
      operator-token bridge works from Mac to Lima. Live Chromium load/API check passes.
- [ ] Browser-driven file and transparent-network approve/retry end-to-end tests;
      multiple simultaneous agents, accurate attribution and stale-request races.
      Pending cards display session ID and project; decisions are disabled if the
      matching active identity is absent. Profile selection/save remain unavailable.
- [ ] UI --detach/status/restart/stop with per-backend singleton lock, safe process
      identity/control, new-token rotation and no interruption of agent sessions.
- [x] Native Bun-only lint/fmt/check/test/build on Mac; Biome and standalone tsc
      removed. Aggregate check probes native command availability with no fallback.
- [x] Install separate Linux ARM64 Bun 1.4.4-canary.1+f33631841 candidate with
      native lint/fmt/check; isolated locked frontend install and native checks,
      tests and build pass. The pre-existing Linux Bun lacks lint. Source the guest
      env first, then use the candidate explicitly (env.sh can reset PATH).
- [x] UI bridge rejects unauthenticated, cross-origin, rebinding and non-approval
      route access; no controller master token in browser. Unit tests pass.
- [ ] Complete accessibility/browser tests, scope confirmation and redaction audit.
- [x] Trusted file learning descriptor + exact read review fixture passes under
      real Syd: initial read denied, approved retry succeeds, write still denied;
      workload fd 3 is closed and cannot write a forged event.
- [ ] File event compound-capability normalization, saved rules, recursive-directory
      approval controls, rename/delete/create fixtures and proc/inherited-FD audit.
- [ ] Forced file umask and workspace metadata-operation compatibility matrix;
      latest fixture needed chmod/chattr for ordinary O_TRUNC, not unsafe overrides.

## Next immediate work

1. Finish transparent veth DNS/hostname + port/transport approval-to-Syd grant wiring.
2. Run real multi-agent file/network approvals from the web UI; no readiness claim
   until both approved retries and bypass attempts are verified.
3. Add directory/saved-file review controls and managed UI background lifecycle.
4. Copy/build Linux lambdap into Lima and prove its real agent workflow; wrapper
   support initially requires no Greywall integration changes.

## Gated migration / cleanup

- [x] Authorized subagent removed claude/lambdap Greywall integration and added
      basic native Syd Guard run/learn + trusted guest-local Mac delegation. It reports
      Go/lambdap race/build/lint/dashboard checks and Linux ARM64 version smoke pass.
- [ ] Independently review child diff and run real lambdap harness workflow; guest
      auth proxy loopback 47100/ephemeral port and user-local config/executable grants
      remain explicit network/filesystem blockers. No paid-model smoke has passed.
- [ ] Keep paused standalone greywall/greyproxy/worktree artifacts untouched unless
      separately authorized; preserve unrelated API proxy/harness/model WIP.

Do not infer full readiness/security parity from this first immutable checkpoint.
