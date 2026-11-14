#!/usr/bin/env bash
# Personal VM provisioning hook. Copy to ~/Developer/.sydguard-provision.sh;
# examples/lima/ai-sandbox.yaml runs it at the end of provisioning (inside the
# VM, as you). Good for private tools that shouldn't live in a shared template.
set -euo pipefail
# Example: build a private CLI from a checkout under ~/Developer.
src="/Users/$USER/Developer/my-private-tool"
if [ -d "$src" ]; then
  (cd "$src" && go build -o "$HOME/.local/bin/my-private-tool" ./cmd/my-private-tool)
fi
