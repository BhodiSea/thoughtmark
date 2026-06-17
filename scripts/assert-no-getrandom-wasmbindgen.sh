#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Feature-unification leak guard (arch P1/§2.2 — the most insidious failure mode). Asserts the alloc-only wasm32
# build of thoughtmark-core does NOT pull in getrandom or wasm-bindgen (those belong only to thoughtmark-wasm).
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

target=wasm32-unknown-unknown
status=0
for crate in getrandom wasm-bindgen; do
  # `cargo tree -i <crate>` succeeds (and prints the inverse tree) only if <crate> is in the graph.
  if cargo tree -p thoughtmark-core --target "$target" --no-default-features --features alloc \
       -e normal -i "$crate" >/dev/null 2>&1; then
    echo "DEP-LEAK: '$crate' is reachable from thoughtmark-core on $target (must be absent)." >&2
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "ok: no getrandom/wasm-bindgen in thoughtmark-core ($target, alloc-only)."
exit "$status"
