# Syd Guard

Go usability/control wrapper around **unmodified upstream Syd**. Linux execution;
macOS delegates into Lima; Windows users run the Linux CLI inside WSL. No Syd
fork, custom syscall engine, TUN dependency, or browser terminal. Foreground
inherits stdio; future persistent attachment delegates to tmux.

Module: `github.com/Gobd/syd-guard`; Go 1.27; urfave/cli v3.14.0.
Development is on the bootstrap feature branch with a draft PR; not a release.

## Status: not yet a complete model-ready workflow

Verified:

- Immutable foreground confinement with the explicit upstream static Syd 3.59.0:
  workspace writes work; outside/control reads/writes and virtual edits are denied;
  a nested child remains confined; raw local TCP is denied.
- Linux controller automatically starts/reuses a private authenticated Unix socket,
  lifetime lock and atomically published token. Named concurrent foreground runs
  get basename/-1/-2 labels; active/history views work through Mac/Lima.
- Trusted file-denial descriptor, live exact-path read review, successful retry,
  and continued write denial pass real Syd fixtures. Workload fd 3 is closed and
  cannot write forged events. Compound operation/preset/alias audits remain pending.
- Embedded React/TypeScript/Bun/vanilla-extract approvals UI works through the Mac
  operator bridge. Live Chromium load/API check and auth/origin/rebinding tests pass.
- Disposable veth/netns/nftables fixtures redirect controlled DNS/synthetic TCP,
  block direct real-IP/host-service routes, recover original destination, and permit
  real example.com/TCP/443 only after approval, with proxy cooperation disabled.
- A private protocol-3 Linux launch has exercised actual synthetic HTTPS and file
  denials, browser approvals through the Mac bridge, and successful retries. A UI
  restart left the test session running. These are narrow fixtures, not an audit.
- Named repo profile discovery/create/show/trust packages and commands have tests.
  Discovered or externally changed permission files are not automatically trusted.

**Unfinished:** opt-in permissive discovery/recording `learn`, strict saved-profile
replay and UI persistence; recursive-directory approval; complete browser-driven
multi-agent/adversarial audit; real standalone agent/tool compatibility; safe
stop/recovery; automatic Lima provisioning; IPv6/non-DNS UDP; Charm TUI.

`TODO.md` is the implementation checklist. Passing fixtures/builds are not a full
sandbox audit or a universal no-bypass guarantee. Don't infer readiness from an
exploratory adapter or this status table.

## Checks / build

```sh
bash scripts/check.sh --fix
bash scripts/check.sh
```

Requires Go, gofumpt, golangci-lint v2, ShellCheck, and a Bun build with **native
lint, fmt and check**. No Biome, Prettier, Oxlint or standalone tsc fallback.
The script probes Bun capabilities and fails clearly if the platform build lacks
those commands. Frontend dependencies are locked in `web/bun.lock`.

```sh
cd web
bun install --frozen-lockfile
bun run fmt
bun run lint
bun run fmt:check
bun run check
bun run test
bun run build
cd ..
go build -o bin/sydguard ./cmd/sydguard
GOOS=linux GOARCH=arm64 go build -o bin/sydguard-linux-arm64 ./cmd/sydguard
limactl copy bin/sydguard-linux-arm64 \
  ai-sandbox:/home/briankemper.guest/.local/bin/sydguard
```

Build frontend assets before Go binaries; Go embeds `internal/webui/assets/`.
Bun is a build/check tool, not a deployed web daemon.

## Upstream engine installation

Inside Linux/Lima/WSL, with Rust/cargo, C build tools, pkg-config, gperf, curl, jq
and development prerequisites:

```sh
# Resolves latest stable candidates; never silently promotes them.
bash scripts/install-upstream-syd.sh
# Exact tested build:
SYD_VERSION=3.59.0 LIBSECCOMP_VERSION=2.6.1 \
  bash scripts/install-upstream-syd.sh
```

Tested guest engine:
`/home/briankemper.guest/.local/opt/syd-3.59.0-static/bin/syd`.
System libseccomp is untouched. Source URLs/build provenance are below.

## Current standalone commands

From this project on Mac, using the existing mirrored-path VM:

```sh
./bin/sydguard run --vm ai-sandbox \
  --syd /home/briankemper.guest/.local/opt/syd-3.59.0-static/bin/syd \
  -- /bin/echo hello
./bin/sydguard sessions --vm ai-sandbox
./bin/sydguard sessions --vm ai-sandbox --history --json
./bin/sydguard ui --vm ai-sandbox
```

Native Linux uses `--backend native`, without Lima. `--name` sets a friendly label;
opaque IDs, not names, identify authority. Current registry entries track the
**foreground supervisor**, not a proven complete descendant lifetime. Completion
means its command returned. Registry is in memory, with at most 256 ended summaries;
controller restart recovery isn't implemented. Workload arguments beyond executable
are not retained in views.

The UI prints an operator-only localhost URL with a short-lived page token. On Mac
it serves embedded assets locally and reaches the guest through Lima. It never
passes the controller master token to the browser. Pending cards show the session
ID and project; decisions are disabled if the matching active session is absent.
The profile view can inspect the nearest existing `default.json` for a known
running project as an **untrusted candidate**, not a selected or applied profile.
It is read-only: production profile editing, saved decisions, session binding,
replay and reload remain unavailable. The authenticated API has an injectable
managed snapshot/CAS interface for a future protected helper, but no production
provider is installed. Saving never changes running permissions. `ui --detach`,
`ui status`, `ui restart` and `ui stop` manage only the bridge, not agent sessions
or controller. A Lima UI bridge and guest CLI must use matching builds.

`run` uses experimental transparent networking by default; it requires passwordless
sudo for bounded per-session namespace setup, and drops privileges before starting
the supervisor. Use `--no-network` for the immutable no-network baseline. There is
no unsandboxed fallback. Advanced transient inputs currently declare exact local
service endpoints and read/execute-only regular files to the trusted launcher.
These are implementation-level caller capabilities, not a normal permission
configuration workflow or workload self-declarations. CLI cleanup and a generic
caller contract remain pending; ordinary permission intent belongs in profiles.

`learn` currently fails explicitly: permissive read/write/public-network bootstrap
and its candidate lifecycle are not wired. Use `run` for denial/review; it does not
produce a finalized profile. Intended learning allows supported nonprotected
reads/writes and vetted public connections without mandatory directory guessing,
then records narrow review candidates; its broad permissions must never be saved.
Upstream `warn` events report permission checks, not successful filesystem I/O:
a DAC-failed attempt can appear, and some missing lookups may not. Candidate
attempt/coverage/loss metadata must survive review and saving. Known secret and
authority paths remain excluded; real writes are irreversible and no secret denylist
is universal. Outside immutable ceilings requires a reviewed restart, not a
fictional live widening. This mode is not implemented or audited.

For a private Lima candidate, `--guest-sydguard /absolute/guest/binary` and
`--guest-config-home /absolute/guest/config` can be passed to both `run`/`learn`
and `ui`; they do not replace an existing installed controller. Implicit Mac
working directories must match a reported mount; `--directory` is an explicit
guest path.

The exploratory proxy adapter is not exposed by the launcher.

## Bounded protected preset

Normal profiles and file approvals share an internally generated name preset:
`.env`, `*.env`, `.env.*`, `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`,
`.netrc`, `.git-credentials`, `.mozilla`, `google-chrome`, `chromium`,
`BraveSoftware`, and `microsoft-edge` components and their descendants are
denied, including metadata. No blanket `.config` denial is applied. Matching is
case-sensitive; other secret names and browser locations are not classified.
Protected controller state, selected engine and launcher executable remain denied.
Explicit trusted inputs and live file approvals cannot override the name preset.
Rules are appended last because Syd uses last-match precedence. Real Syd 3.59.0
fixtures cover the three env name forms at several depths, selected credential
directories, symlink following, and creation of a new hardlink. A preexisting
hardlink under an unrelated name can bypass pathname-based protection, including
secret reads: do not place such aliases in the workspace. This is not a universal
secret classifier or a proven inode-level boundary. Other aliases, inherited
FDs, concurrent renames and browser locations remain subject to audit. Future
permissive learn must reuse this preset; learn is not implemented.

## Checkpointed experimental components

The source includes a strict file-profile compiler, a bounded review-only
permission-check collector, Linux managed-policy helper/admin/client code, and
an unactivated managed-client profile adapter for explicitly registered refs.
They are **not connected to normal selected-profile launches or production UI
editing**. `learn` still fails explicitly; a compiler or collector package is not
an implemented learning workflow. Do not install/enable the privileged helper
without the remaining deployment and integration review. Experimental snapshot
responses include registered identity and namespace observations; the client checks
exact returned bytes and typed revision conflicts. These checks do not pin a project
namespace through later consumption. The stricter wire format requires matched
helper/client builds. The adapter verifies an explicit bounded set of registered
project/profile pairs through authenticated reads, maps helper CAS conflicts, and
rejects changed bindings without reopening metadata paths. It is not an automatic
helper catalog or a pinned launch namespace; its tests use an injected transport,
not a deployed helper. Uncertain saves carry an explicit indeterminate outcome
through the API/bridge; the editor preserves drafts and blocks blind retry until
an explicit fresh snapshot is loaded. Profile helper work shares a six-second
cooperative budget inside a ten-second profile transport budget; existing live
approval routes do not inherit that timeout. Profile lookup does not wait for
session teardown; catalog refreshes do not overlap and live-status polling has an
independent lifecycle with bounded read-only fetches. These are application deadlines,
not universal kernel/filesystem-hang bounds. Lost save responses remain uncertain
rather than proof of failure. Production integration remains gated. Shared mounts and
Darwin managed storage remain unsupported. See the temporary `HANDOFF.md` for the
resumed integration state and next steps.

`internal/webui/assets` is intentionally tracked: Go embeds it, allowing a clean
Go-only build and module installation. Rebuild from `web/src` with supported Bun
before building Go, and verify the generated assets stay in sync.

## Named project configs

Intended user layout:

```text
repo/.sydguard/default.json
repo/.sydguard/build.json
repo/.sydguard/restricted.json
```

Implemented discovery/review commands:

```sh
./bin/sydguard profile --directory /path/to/repo --name build create
./bin/sydguard profile --directory /path/to/repo --name build show
./bin/sydguard profile --directory /path/to/repo --name build trust --yes
```

Nearest `.sydguard` discovery walks upward. Missing named profiles start empty.
Review hashes live outside agent-writable projects; changed/unreviewed files lose
trust. **`run --config NAME`, launch replay and UI-save wiring are pending**.

### Protection decision: readable intent, protected authority

This is the chosen layered design, **not a completed launch feature**:

1. **Syd read/mutation rules.** Normal launches deny write, create, delete,
   rename, truncate, chmod, chattr, mkdir, rmdir and symlink operations on the
   workspace `.sydguard` and its children, while allowing reads under the usual
   workspace ceiling. Workspace-root rename/delete/rmdir are denied and file
   approval rejects policy ancestors. Existing policy-directory symlinks are
   rejected. These path rules do not protect preexisting hardlink aliases, and
   the managed authority and launch replay are not wired.
2. **Inode-level protection as well.** A real upstream Syd 3.59.0 fixture showed
   that a preexisting writable hardlink elsewhere in the workspace can mutate
   the profile's underlying inode despite canonical-path denies. A read-only
   bind of just the canonical file/directory does not fix the other alias.
   A same-UID chmod is also insufficient: the owner can change it back.
   Upstream's Syd 3.59.0 `syd(7)` manual documents
   [Trusted Hardlinks](https://man.exherbo.org/syd.7.html#Trusted_Hardlinks):
   default checks constrain **creation** of new hardlinks, including requiring
   the target to be readable/writable by the caller. This is not a documented
   promise to make a denied pathname's inode immutable through every
   preexisting alias. The README links to the threat model/manual; it does not
   explicitly warn about this particular preexisting-alias case. Our retained
   runtime regression, not an assumption about the README, establishes the
   wrapper's limitation. We have not classified it as an upstream vulnerability
   or reported it upstream.
3. **Reviewed snapshot, not live editable authority.** Launches must consume a
   defensive reviewed snapshot. Protected trust/revision records live outside
   the checkout; discovered or changed JSON must not automatically authorize
   anything. Snapshot, merge and revision-comparison primitives exist, but they
   are not an atomic managed store or completed launch/save implementation.
4. **Explicit managed writes.** The proposed bounded privileged helper owns
   only fresh managed `.sydguard` inodes and performs validated named-profile
   transactions with expected revisions. It must never chown a preexisting
   hardlinked inode, modify unrelated repo files, expose arbitrary root writes,
   or make the agent/Syd broker privileged. Existing unmanaged configs require
   explicit reviewed adoption, not silent migration. Experimental Linux helper,
   admin and client source exists, but production integration and deployment
   remain gated; no production provider is installed.

**Verified platform limits:** a disposable root-owned policy on VM-local Linux
storage resisted tested canonical/alias writes and chmod by the unprivileged
workload. The same guest-root ownership on `/workspace` virtiofs **did not**:
UID 502 could write/chmod both paths. VM-local DAC cannot be assumed to protect
Mac-backed files. Managed registration must fail closed on unsupported shared
mounts. A host-root-owned backing-inode counterpart needs a separate disposable
administrator-assisted test; no real project ownership changes or host helper
installation have occurred. Mac-mounted repo protection remains a core blocker.

Project policy is intended to be agent-readable so agents can understand their
limits. **Tokens, controller state, trusted logging channels and helper
credentials are different: they stay completely unreadable and inaccessible.**
The agent cannot edit policy JSON or call the approval channel to self-authorize.
Do not treat the current `profile create/trust` commands as a mutation-protected
managed store, or claim Syd path rules alone solve hardlinks.

Per-run approvals must never silently change a file. Explicit saving updates
only the selected profile, checks its expected revision, and must preserve or
reject concurrent operator edits rather than overwrite them. File intent
specifies a literal path, the public `read`/`write`/`delete` access groups and
recursive scope; the compiler maps these to distinct Syd operations. Empty paths and arbitrary
wildcards must not grant everything. No-delete does not preserve editable
content: write/truncate can still destroy it. Persist network intent as exact
hostname/port/transport, never resolved IPs; rebuild runtime bindings on launch.

## Network boundary / acceptance criteria

One Linux network namespace + veth per run, with session-owned nftables rules.
No TUN/packet stack/relay daemon; no global forwarding or VM default-route edits.
Links remain down until the deny firewall is installed; workload executes as a
non-root user with no network-administration capability.

Controlled DNS returns never-reassigned session-local synthetic addresses for
hostnames. A trusted actual connection supplies **port + transport**; DNS never
guesses a port. Persistent config stores only logical hostname/port/transport.
Fresh launches start with fresh Syd rules and mappings, not old IP permissions.
Only approved synthetic endpoints should receive live Syd grants; the transparent
Go gateway independently checks logical permission before vetted public dialing.

Direct real-IP/alternate DNS/control-plane routes are denied. Private/loopback/
link-local/metadata and mixed public/private DNS answers fail closed unless a
specific trusted service contract is explicitly implemented. Separate sessions
must not inherit each other's mappings/grants. Initially TCP + controlled TCP/UDP
DNS only; IPv6 and other UDP/QUIC stay denied until implemented/tested.

A named-route grant controls routing, not arbitrary encrypted application identity.
Shared-IP virtual hosting, mismatched SNI/HTTP Host, ECH and upstream relay services
require honest scope descriptions/protocol-aware enforcement for stronger claims.
Approved destinations can still carry exfiltration; there is no content-safety promise.

Required remaining adversarial gates include hard-coded/mapped IPs, DoH/DoT/hosts
files, different port/transport, other-session aliases, expiry/rebinding, raw sockets,
setns/routes/TUN mutation, inherited/proc FDs, operator path/socket access, component
termination, approval/revoke races, stale identities and resource collision cleanup.

## Runtime fixtures

Inside Linux/VM:

```sh
bash scripts/integration.sh
SYDGUARD_TEST_WRAPPER=/path/to/sydguard bash scripts/session-smoke.sh
SYDGUARD_TEST_SYD=/path/to/syd go test -race -v ./internal/files -run Integration
# Explicit disposable root networking fixture, requiring sudo/ip/nft/public HTTPS:
SYDGUARD_NETNS_INTEGRATION=1 \
  go test -race -v ./internal/network ./internal/netns -run 'Veth.*Integration'
```

Default-hardening runtime gates use no `trace/allow_unsafe` override. Queues are
bounded; approvals permit a retry, not a fictional paused-syscall resume. Once
scopes must stay unavailable unless an atomic backend primitive is demonstrated.

## Lima defaults / platform behavior

```sh
./bin/sydguard config path
./bin/sydguard config show
./bin/sydguard config lima set ~/configs/agent.yaml
./bin/sydguard config lima show
./bin/sydguard config lima edit
```

These private launcher defaults are separate from readable project profiles.
Mac base: `~/Library/Application Support/sydguard`; Linux usually
`~/.config/sydguard`. Controller authority is under its private `state/` tree;
unsafe writable ancestors are rejected. Lima recipe set records SHA256; edit uses
simple VISUAL/EDITOR argv without shell evaluation. These commands never restart
or provision VMs. Automatic reuse/init/mount mapping/fresh-instance handling remains
pending. VM mounts and immutable kernel ceilings cannot be widened by a live grant.

`doctor` still reports complete workflow readiness false. Windows means the Linux
CLI inside WSL; kernel/backend capabilities must be probed, not inferred by version.

## Examples

- [`examples/lima/ai-sandbox.yaml`](examples/lima/ai-sandbox.yaml): generic
  development VM resources, a project mount, Go 1.27 setup and loopback-only
  development forwarding for ports 1024–10000. `limactl validate` passes; fresh
  VM provisioning has not been tested. Review mounts before use. This recipe is
  independent of any particular agent application.
- [`examples/profiles/default.json`](examples/profiles/default.json): illustrative
  current permission schema with project editing, common Go/npm cache paths and
  exact public host/TCP/443 rows. It is **not** a generated learning result or a
  complete toolchain policy. Custom cache paths, install destinations and download
  hosts may differ. Strict profile launch/replay remains unfinished; copying this
  file does not activate or protect permissions.

The same embedded approvals UI serves native Linux, macOS through Lima, and
Linux inside WSL. Browser UI code is platform-independent; backend adapters and
compiled Go binaries differ by platform. VM dev-port forwarding does not publish
an isolated Syd namespace's server without separate session-publishing support.

## Upstream provenance / installation findings

Experiments: Ubuntu 24.04 ARM64 Lima ai-sandbox, kernel 6.8.0-147; no Syd source
patches. System libseccomp 2.5.5 lacked `seccomp_export_bpf_mem`; checksum-verified
upstream 2.6.1 was built user-locally. An initial dynamically linked 3.59.0 PIE
segfaulted in executable-mapping hardening; diagnostic `allow_unsafe_noxom` findings
were **not** accepted as a launch gate. The public upstream static recipe worked:

```sh
LIBSECCOMP_LINK_TYPE=static
LIBSECCOMP_LIB_PATH="$(pkg-config --variable=libdir libseccomp)"
RUSTFLAGS="-Ctarget-feature=+crt-static"
cargo build --release --locked -j2
```

We follow only the build configuration, never upstream publishing/host-management
steps. Static 3.59.0 passes current default-hardening fixtures; no silent upgrade
or downgrade. Profile parent directories must be private (0700), not only files
0600. ARM64 may lack `/lib64`; emit Landlock rules only for existing paths. FS-kind,
path and Landlock layers are distinct. AppArmor was not disabled; an experimental
userns exemption did not fix the dynamic crash and isn't proven required setup.

Comparison-only official static ARM64 3.53.0 archive was signature-verified using
Signify-style Ed25519, not OpenPGP. Upstream key came over HTTPS without independent
out-of-band authentication; don't overclaim its trust. Features differed (`+trusted`
vs local default `-trusted`), so comparison does not establish equivalent security.

- Archive SHA256: `5a74e58238e14fae0e0bc41925a8e8a9f1994eedda8d38def971e2212439021b`
- Key-file SHA256: `dd38549f3b5ccdd8d49a08a817e73e24d4c2d71d68e1c4f89a1b1bbed13a6e4d`
- Signature SHA256: `ac2bf3dcd6bfde9d1afae0b42b2ef945610cc7eaae9579887308ca84ba6be459`

Sources:
- https://gitlab.exherbo.org/sydbox/sydbox (unmodified engine)
- https://gitlab.exherbo.org/sydbox/sydbox/-/blob/main/dev/release.sh (static recipe)
- https://github.com/seccomp/libseccomp/releases/tag/v2.6.1
- https://distfiles.exherbo.org/sydbox/syd-3.53.0-aarch64-unknown-linux-gnueabi.tar.xz
- https://gitlab.exherbo.org/sydbox/sydbox/-/raw/main/dev/syd-release.pub
- https://man.exherbo.org/syd.1.html
- https://man.exherbo.org/syd.2.html (protocol/IP/port rules; hostnames unsupported)

Distribution/API/kernel/license review is still required before shipping. No
private enforcement fork, own PTY server, TLS-MITM stack or universal kernel-exploit
resistance is claimed by this wrapper.

## Profile schema and trusted caller inputs

`examples/profiles/default.json` illustrates version 1 syntax; it is not an
automatically imported or universally safe policy. File rules have a literal
`path`, an `access` array containing only `read`, `write`, and/or `delete`,
and an explicit `recursive` boolean. Read covers content, metadata, listing,
traversal and readlink. Write covers creation, modification, truncation,
chmod/chattr, mkdir and symlink, but not entry removal. **Write can destroy file
contents even without delete.** Delete covers unlink, rmdir and rename/replace;
atomic-saving editors may need it. Execution is a separate trusted runtime
requirement, not implied by write. Network rules remain exact host/port/transport.
Legacy `capabilities` fields must be manually migrated; they are rejected.
Saved-profile storage, loading and replay are not yet launch authority; permissive
learning and recording observed narrow groups are future work. The intended
bootstrap includes supported public network access, narrowly recorded, with known
protected paths and targets excluded; it is not implemented.

Advanced trusted callers can currently supply narrow exact runtime inputs and a
single named service through the internal launcher/controller interface; these
are not ordinary profile-based workflow. Service names are lowercase DNS labels;
the exact `NAME.sydguard.internal` TCP endpoint maps only to its declared
`127.0.0.1:PORT`. Other reserved names and ports are not auto-granted.
