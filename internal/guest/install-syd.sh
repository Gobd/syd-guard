#!/usr/bin/env bash
# Install the tested upstream Syd (unmodified) for sydguard, inside Linux.
#   sydguard setup        (runs this script; from the Mac it runs in the VM)
# Pinned: Syd 3.59.0 via `cargo --locked` (crates.io checksums) and
# libseccomp 2.6.1 (sha256 below), built static. Installs root-owned to
# /usr/local/libexec/sydguard/syd and lets that one binary create user/mount
# namespaces under AppArmor (private DNS + build-folder overlays). Needs sudo.
set -euo pipefail
SYD_VERSION=3.59.0
SECCOMP_VERSION=2.6.1
SECCOMP_SHA256=501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be
ENGINE=/usr/local/libexec/sydguard/syd

case "$(uname -m)" in
  aarch64) target=aarch64-unknown-linux-gnu ;;
  x86_64) target=x86_64-unknown-linux-gnu ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

if ! "$ENGINE" --version 2>/dev/null | grep -q "^syd $SYD_VERSION"; then
  if command -v apt-get >/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential pkg-config gperf curl ca-certificates >/dev/null
  fi
  command -v cargo >/dev/null || [ -x "$HOME/.cargo/bin/cargo" ] || curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
  work="$HOME/.cache/sydguard-build"
  mkdir -p "$work" && cd "$work"
  curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v$SECCOMP_VERSION/libseccomp-$SECCOMP_VERSION.tar.gz" -o libseccomp.tar.gz
  echo "$SECCOMP_SHA256  libseccomp.tar.gz" | sha256sum -c -
  rm -rf "libseccomp-$SECCOMP_VERSION" && tar -xzf libseccomp.tar.gz
  prefix="$work/libseccomp-$SECCOMP_VERSION-static"
  (cd "libseccomp-$SECCOMP_VERSION" && ./configure --prefix="$prefix" --enable-static >/dev/null && make -j"$(nproc)" >/dev/null && make install >/dev/null)
  export LIBSECCOMP_LINK_TYPE=static LIBSECCOMP_LIB_PATH="$prefix/lib" RUSTFLAGS="-Ctarget-feature=+crt-static"
  export PKG_CONFIG_PATH="$prefix/lib/pkgconfig" CARGO_TARGET_DIR="$work/syd-target"
  echo "building syd $SYD_VERSION (takes a while)…"
  cargo install --locked syd --version "$SYD_VERSION" --target "$target" --root "$work/syd" --bin syd
  sudo install -D -m 0755 -o root -g root "$work/syd/bin/syd" "$ENGINE"
fi
"$ENGINE" --version | head -1
HELPER=/usr/local/libexec/sydguard/net-helper
if [ -n "${SYDGUARD_HELPER_SOURCE:-}" ]; then
  sudo install -D -m 0755 -o root -g root "$SYDGUARD_HELPER_SOURCE" "$HELPER"
fi

if [ -d /etc/apparmor.d ] && command -v apparmor_parser >/dev/null; then
  sudo tee /etc/apparmor.d/sydguard-engine >/dev/null <<APPARMOR
abi <abi/4.0>,
include <tunables/global>
# sydguard: let the root-owned Syd engine create user/mount namespaces.
profile sydguard-engine $ENGINE flags=(unconfined) {
  userns,
}
# The helper creates only its own user/net namespaces; it is not setuid.
profile sydguard-network $HELPER flags=(unconfined) {
  userns,
}
APPARMOR
  sudo apparmor_parser -r /etc/apparmor.d/sydguard-engine
fi
"$ENGINE" -poff -m unshare/user:1 -m unshare/mount:1 -- /bin/true && echo "ok: $ENGINE (namespaces available)"
