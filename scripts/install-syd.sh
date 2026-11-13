#!/usr/bin/env bash
# Build the tested upstream Syd (unmodified) as a static binary, inside Linux.
# Pinned: Syd 3.59.0 via `cargo --locked` (crates.io checksums) and
# libseccomp 2.6.1 (sha256 below). Installs to ~/.local/opt/syd-3.59.0-static.
set -euo pipefail
SYD_VERSION=3.59.0
SECCOMP_VERSION=2.6.1
SECCOMP_SHA256=501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be
case "$(uname -m)" in
  aarch64) target=aarch64-unknown-linux-gnu ;;
  x86_64) target=x86_64-unknown-linux-gnu ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
root="$HOME/.local/opt/syd-$SYD_VERSION-static"
if "$root/bin/syd" --version 2>/dev/null | grep -q "^syd $SYD_VERSION"; then echo "already installed: $root/bin/syd"; exit 0; fi
command -v cargo >/dev/null || { curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal; }
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
work="$HOME/.cache/sydguard-build"; mkdir -p "$work"; cd "$work"
curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v$SECCOMP_VERSION/libseccomp-$SECCOMP_VERSION.tar.gz" -o libseccomp.tar.gz
echo "$SECCOMP_SHA256  libseccomp.tar.gz" | sha256sum -c -
rm -rf "libseccomp-$SECCOMP_VERSION" && tar -xzf libseccomp.tar.gz
prefix="$HOME/.local/opt/libseccomp-$SECCOMP_VERSION"
(cd "libseccomp-$SECCOMP_VERSION" && ./configure --prefix="$prefix" --enable-static >/dev/null && make -j"$(nproc)" >/dev/null && make install >/dev/null)
export LIBSECCOMP_LINK_TYPE=static LIBSECCOMP_LIB_PATH="$prefix/lib" RUSTFLAGS="-Ctarget-feature=+crt-static"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig" CARGO_TARGET_DIR="$work/syd-target"
cargo install --locked syd --version "$SYD_VERSION" --target "$target" --root "$root" --bin syd
"$root/bin/syd" --version | head -1
"$root/bin/syd" -poff -- /bin/true && echo "ok: $root/bin/syd"
