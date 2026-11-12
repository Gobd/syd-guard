#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  printf 'Run this upstream-build script inside Linux/Lima/WSL, not on the Mac.\n' >&2
  exit 1
fi
case "$(uname -m)" in
  aarch64) target=aarch64-unknown-linux-gnu ;;
  x86_64) target=x86_64-unknown-linux-gnu ;;
  *) printf 'Unsupported build architecture\n' >&2; exit 1 ;;
esac
# Requires the upstream Rust toolchain, C build tools, pkg-config and gperf.
# This source build is guest-only and never replaces the system libseccomp.
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
command -v jq >/dev/null 2>&1 || { printf 'Missing jq for release discovery\n' >&2; exit 1; }
version="${LIBSECCOMP_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(curl -fsSL https://api.github.com/repos/seccomp/libseccomp/releases/latest | jq -er '.tag_name | sub("^v"; "")')"
fi
syd_version="${SYD_VERSION:-}"
if [[ -z "$syd_version" ]]; then
  syd_version="$(curl -fsSL https://index.crates.io/3/s/syd | jq -ser '[.[] | select(.yanked == false and (.vers | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")))] | sort_by(.vers | split(".") | map(tonumber)) | last | .vers')"
fi
for release in "$version" "$syd_version"; do
  [[ "$release" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Invalid stable release: %s\n' "$release" >&2; exit 1; }
done
printf 'Resolved candidates: libseccomp %s; Syd %s\n' "$version" "$syd_version"
prefix="$HOME/.local/opt/libseccomp-$version"
work="$HOME/.cache/sydguard-build/libseccomp-$version"
mkdir -p "$work"
cd "$work"
curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v$version/libseccomp-$version.tar.gz" -o "libseccomp-$version.tar.gz"
curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v$version/libseccomp-$version.tar.gz.SHA256SUM" -o SHA256SUM
sha256sum -c SHA256SUM
tar -xzf "libseccomp-$version.tar.gz"
cd "libseccomp-$version"
./configure --prefix="$prefix" --enable-static
make -j4
make install
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
# Upstream dev/release.sh uses static libseccomp + crt-static. Keep this
# candidate separate from any existing Syd install until runtime tests pass.
export LIBSECCOMP_LINK_TYPE=static
export LIBSECCOMP_LIB_PATH="$prefix/lib"
export RUSTFLAGS="-Ctarget-feature=+crt-static"
export CARGO_TARGET_DIR="$HOME/.cache/sydguard-build/syd-static-target"
root="$HOME/.local/opt/syd-$syd_version-static"
cargo install --locked syd --version "$syd_version" --target "$target" --root "$root" --bin syd --bin syd-lock
printf '\nUpstream static Syd candidate installed (no source patches, not selected as default).\n'
"$root/bin/syd" --version
"$root/bin/syd" --check
printf '%s\n' "$root/bin/syd" > "$HOME/.cache/sydguard-build/current-static"
printf 'Run integration with SYDGUARD_TEST_SYD=%s; no engine default was changed.\n' "$root/bin/syd"
