#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Dependency-direction invariant (I8, arch §3.3). Arrows point INWARD to core; no plugin or networking crate is
# ever a (transitive) dependency of thoughtmark-core. Fails the build if core's dependency closure contains any
# plugin crate or any networking/ambient-entropy crate. Wired now against stubs (ADR-0004 keeps the graph legible).
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

forbidden='^(thoughtmark-(anchor|anchor-ots|anchor-rfc3161|anchor-fabric|identity|attest-tee|c2pa|log|redaction|monitor|wasm)|getrandom|wasm-bindgen|tokio|reqwest|hyper|h2|rustls|native-tls|mio|socket2)$'

# core's full forward dependency closure (package names only).
deps="$(cargo tree -p thoughtmark-core -e normal --prefix none --format '{p}' 2>/dev/null \
        | awk 'NF{print $1}' | sort -u)"

leak="$(printf '%s\n' "$deps" | grep -E "$forbidden" || true)"
if [ -n "$leak" ]; then
  echo "DEP-DIRECTION VIOLATION (I8): thoughtmark-core's closure contains forbidden crate(s):" >&2
  printf '  %s\n' "$leak" >&2
  exit 1
fi
echo "ok: thoughtmark-core depends only inward (no plugin/networking/entropy crates)."
