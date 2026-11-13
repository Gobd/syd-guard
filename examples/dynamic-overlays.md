# Deny-first build-folder overlays

Configured `keepOnVM` names are reserved in new sessions, not merely scanned once.
Stock Syd denies access to unprepared paths, including directory creation,
symlink creation, and metadata/O_PATH access. The daemon reacts to denials:

1. Verify that the folder is configured and covered by an existing literal,
   recursive write grant (and the session's optional Landlock ceiling).
2. Lock the target and its ancestors against rename/delete in this session.
3. Install and verify the bind mount in the running sandbox's namespace.
4. Apply the mounted-path exemption through Syd IPC, retaining global guards
   and protected-path denies. Only then does access become available.

The original operation fails; the application/user must retry. There is no
suspended filesystem syscall callback in this integration. Mount failures leave
access denied and are reported, rather than falling back to host storage.

## Controls and compatibility

- Automatic `target` preparation requires adjacent `Cargo.toml`, preserving the
  Rust manifest check. Without it, the folder stays denied, with a UI explanation.
- **Create overlay** on the UI card overrides the manifest requirement, not the
  mount verification or permission checks. `sydguard overlay add PATH` does the
  same through the agent's session broker. Operators can use `--session ID` on
  the execution machine. Neither route accepts an arbitrary mount source.
- Forced paths are reused on later sessions. Daemon restart preserves mounts;
  repeated requests verify rather than stack mounts. Revocation withdraws the
  exemption without revealing original host contents.
- Configured names are genuinely reserved: existing symlinks/files there are
  refused, and an unrelated `target` directory without a manifest is not silently
  exposed. Remove `target` from machine config and restart if it is ordinary data.
- Already-authorized installed toolchains inside `node_modules` retain read/exec
  access. Those roots are frozen read-only for the session and listed in the UI;
  forcing a writable overlay there requires a new session because directory FDs
  may already have escaped. Launch paths are handled before executing the agent.
- Mount ancestors cannot be renamed/deleted by that session. This restriction
  prevents moving a parent and recreating an unmounted directory at an allowed
  pathname. Moving unrelated directories remains allowed.
- Startup includes saved write grants. Rules outside Landlock's ceiling are
  skipped without mounting, matching the parent branch's saved-but-skipped model.
- Scans are bounded at 20,000 entries; sessions at 256 overlays. Excessive scans
  fail visibly. Sessions predating deny-first enforcement require a new launch.

## Go-only mount helper

The runtime has no Python/C dependency. A short-lived copy of sydguard opens the
sandbox's namespace descriptors, then forks a single-thread child. That child
uses only raw syscalls with signals blocked: enter user/mount namespaces,
no-follow directory walks, `open_tree`/`move_mount`, verify the source inode is
visible at the target, exit. It never returns to the Go runtime. The daemon does
not change its own namespaces. Namespace-local capabilities suffice; no
host-root mount privileges or setuid helper are needed.

The child path must remain allocation-free, non-splitting and non-instrumented.
Supported builds are Linux amd64/arm64; live mounting needs the Linux 5.2 mount
API. Normal pinned engine/helper installation still requires setup privileges.
This low-level helper has not had an independent security audit.

## Tests and investigation

Python is acceptance-test tooling only:

```sh
python3 scripts/dynamic-overlay-e2e.py /path/to/sydguard
E2E_LANDLOCK=1 python3 scripts/dynamic-overlay-e2e.py /path/to/sydguard
```

Real Syd 3.59.0 / Lima tests cover:

- Mount-before-grant for an approved sibling project.
- O_PATH denied for an unmounted host directory introduced after startup.
- Automatic preparation for a newly created package, without a manual command.
- Late Cargo manifest, plus forced preparation without any manifest.
- Symlink and rename introduction denied; moving a mounted ancestor denied.
- Revocation without leaving a mounted-path exemption.
- Same-PID daemon restart, explicit verification, and reuse on a new launch.
- Failed symlink-target preparation withholding the grant, including relaunch.
- Installed agents launched from read-only `node_modules` remain executable and
  cannot modify their own toolchain tree.
- All of the above with and without Landlock.

The initial mkdir-only experiment proved denial → mount → retry works, and even
blocked directory rename, but **allowed symlink introduction**. A late-mount-only
experiment also demonstrated that an already-open directory FD could still write
the original host folder. Those are why the final version guards all relevant
access, including stat/O_PATH, before exposing the folder. It is not just the
original mkdir-only experiment with an automatic retry bolted on.

## Boundary and remaining work

These guards protect configured output paths in a session. They do **not** make
a writable host share safe from arbitrary project code. Install scripts can
write other permitted paths, directly or via links into source directories.
Other host processes or other sandboxes can move/change shared paths outside
this session's rules; there is no cross-session inode transaction. Do not move
mounted ancestors externally while a session uses them.

Existing contents are hidden, not migrated/deleted. Previously opened handles
cannot be redirected by mounting; new guarded sessions prevent acquiring them
from an unprepared reserved path. Multi-session updates are not globally atomic.

Further work: package-manager compatibility runs (npm/pnpm/uv/Cargo), hostile
cross-session/host rename testing, richer UI overlay inventory, explicit cache
lifecycle controls, and Linux amd64 runtime coverage (currently cross-built;
real helper tests were on Linux arm64). For a guarantee of no direct host-tree
writes, use a VM-local checkout and explicitly export selected changes instead
of relying on output-folder names.
