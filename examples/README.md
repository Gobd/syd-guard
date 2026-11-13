# Example configurations

Choose **one machine config**, review/edit it, then copy it to
`~/.config/sydguard/config.json` on the machine where you launch sydguard.
These files are alternatives, not layers automatically merged together.
No host commands are configured by default.

| Machine config | Backend | Landlock | Intended use |
| --- | --- | --- | --- |
| [`config-lima.json`](config-lima.json) | Lima | Off | Recommended starting point: VM containment, unrestricted live approval workflow. |
| [`config-native.json`](config-native.json) | Native Linux | Off | Explicitly run on this Linux host without a VM. |
| [`config-lima-landlock.json`](config-lima-landlock.json) | Lima | On | VM plus a fixed filesystem ceiling; pairs with [`lima/landlock.yaml`](lima/landlock.yaml). |
| [`config-native-landlock.json`](config-native-landlock.json) | Native Linux | On | No VM, but a fixed kernel filesystem ceiling in addition to Syd. |
| [`config.json`](config.json) | Lima | Off by default | Full development example with optional host-broker command definitions. Review every command before using it. |

## Backend and VM selection

- `backend`: `lima` or `native`. Default outside a Lima guest is **Lima on both
  macOS and Linux**. Native execution requires Linux and an explicit opt-in.
- `vm`: the Lima **instance name**, such as `ai-sandbox` or `agent-ceiling`.
- `lima`: a **YAML configuration file**, used only when creating a missing VM.
  Changing it does not reconfigure an existing instance.
- CLI flags override the corresponding config settings. `SYDGUARD_BACKEND`,
  `SYDGUARD_VM`, and `SYDGUARD_LIMA` can also supply defaults. An explicit
  `--vm`/`--lima` selects Lima; combining either with `--backend native` is an error.
- Failure to find/start Lima never falls back to running on the host.
- Inside an existing Lima guest, native execution is the default; the outer
  launcher explicitly selects native for the inner launch to avoid recursion.

```sh
sydguard -- pi                           # Lima by default
sydguard --vm work-agent -- pi           # select a VM instance
sydguard --vm work-agent --lima ./vm.yaml -- pi
sydguard --backend native -- pi          # explicit Linux host execution
sydguard --backend native setup          # install the native engine/helper
```

The built-in macOS VM uses VZ/virtiofs; the Linux default uses QEMU/virtiofs and
requires the corresponding Lima/QEMU dependencies plus the host's Rust `virtiofsd` (QEMU's older C
virtiofsd needs root and doesn't work with rootless Lima); guest kernels need
`CONFIG_VIRTIO_FS`, standard on current Ubuntu images. Both share `~/Developer`
writable. Narrow the YAML mounts if you want less host data exposed.

## Optional Landlock: multiple roots, one fixed ceiling

Landlock is **off by default**. It is available with either backend, including
inside Lima, and requires Linux Landlock ABI 3 or newer. If explicitly enabled
but unavailable, the session fails to start—there is no silent downgrade.

For example (the native-Linux variant):

```json
{
  "backend": "native",
  "landlock": {
    "enabled": true,
    "read": ["~/datasets", "~/reference"],
    "write": ["~/Developer", "~/.cache", "~/scratch"]
  }
}
```

Create those directories first, or replace them with existing roots. Lists take
literal files/directories, not globs. `read` includes execute; `write` includes
read. Paths are resolved at session startup, including symlinks.

**These roots are maximum permissions, not grants to the agent.** Syd still
starts with its usual narrow permissions. Approving a read/write inside the
ceiling works live, as does revocation of Syd grants. A wider ceiling requires
changing config and starting a **new session**; daemon restart does not widen it.
Outside-ceiling live approvals are rejected rather than saved as applied.
Trusted rules-file changes that exceed the ceiling mark the session
`restart-required`.

The ceiling automatically includes the existing Syd baseline: system/runtime
reads, the current project and temporary directories for read/write, launch
executables, terminal devices, and private resolver/build-overlay storage.
Configured roots **extend** that baseline; they do not replace it. The Sessions
UI lists the effective roots. This is not a mode for forbidding `/tmp`, for
example. Filesystem metadata operations are not all covered by Landlock; Syd
remains the main policy layer.

```sh
sydguard --landlock -- pi                # enable using baseline + configured roots
sydguard --landlock=false -- pi          # explicitly disable for this launch
```

Even `--learn` cannot exceed an enabled kernel ceiling. Some kernel-only denials
may not produce a Syd approval card. Leave Landlock off if arbitrary new
filesystem approvals without restarting are essential to your workflow.

### Lima Landlock example

1. Edit the `lima` filename in `config-lima-landlock.json` to point at your clone.
2. Create/edit the **host** directories `~/Developer`, `~/datasets`, `~/reference`.
3. Review [`lima/landlock.yaml`](lima/landlock.yaml). It maps those directories to
   `/work/projects` (writable), `/work/datasets` (read-only), and
   `/work/reference` (read-only). It also creates VM-local `/work/cache`.
4. Copy the config and run `sydguard vm start`, then launch from a shared project.

Landlock paths are interpreted **on the execution machine**: inside the Linux
VM for Lima, on the host for native. Thus the Lima example uses `/work/...`, not
the host's `~/Developer`. A `~` in Landlock config refers to the guest user's
home when using Lima. This differs from the `lima` filename and `env` secret
files, which are read on the host.

The portable example YAML uses QEMU/virtiofs (Linux hosts need the Rust `virtiofsd`). On
macOS you may choose VZ instead. A read-only VM share cannot become writable through a Syd approval or
Landlock config. Likewise, a file not shared into the VM remains unavailable.

## Other examples

- [`config.json`](config.json): VM defaults, helper ports, secret environment
  variables (`file:` reads a protected host file), build overlays, and optional
  host commands: push `agent/*`, PRs, issues, GitHub Actions, CircleCI.
  These commands execute **outside the sandbox and VM**, with your host
  credentials. Some examples use `allow`; remove them or use `ask` if you want
  approval each time. No shell interpolation is used, but an authorized program
  can still execute code or access credentials: this is a deliberate sandbox exit.
- [`sydguard.json`](sydguard.json): project policy; copy as `.sydguard.json` in the
  launch folder. Backend and Landlock settings belong in the protected machine
  config, not in this agent-adjacent project rules file.
- [`AGENTS-snippet.md`](AGENTS-snippet.md): guidance for `AGENTS.md`/`CLAUDE.md` so
  agents know how to request brokered commands.
- [`lima/ai-sandbox.yaml`](lima/ai-sandbox.yaml): full coding VM (Go, Node/pnpm,
  Bun, uv, Playwright, Claude/Codex/Pi, linters); macOS VZ configuration.
- [`provision.sh`](provision.sh): personal hook for private tools; copy to
  `~/Developer/.sydguard-provision.sh`.
