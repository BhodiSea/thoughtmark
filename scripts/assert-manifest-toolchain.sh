#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Manifest-toolchain parity (arch §12.5, §16; qf Domain 7). The reproducible artifacts (the .wasm, the corpus) are
# only byte-stable under the pinned toolchain, so `spec/vectors/manifest.json`'s `toolchain` block records the
# canonical {rustc, wasm_bindgen, wasm_opt}. This asserts the live tools match that record (and that wasm_opt
# stays disabled — re-enabling binaryen would put a non-byte-stable tool on the reproducible path). Enforced in CI
# (or with THOUGHTMARK_ENFORCE_TOOLCHAIN=1); locally it prints any drift as a warning so `just ci` stays green off
# the pinned host.
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

MANIFEST="spec/vectors/manifest.json"
enforce=false
{ [ "${CI:-}" = "true" ] || [ "${THOUGHTMARK_ENFORCE_TOOLCHAIN:-}" = "1" ]; } && enforce=true

want() { grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$MANIFEST" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'; }
want_rustc="$(want rustc)"
want_wb="$(want wasm_bindgen)"
want_opt="$(want wasm_opt)"

got_rustc="$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '?')"
got_wb="$(wasm-bindgen --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '?')"

fail=0
check() {
  local name="$1" want="$2" got="$3"
  if [ "$want" != "$got" ]; then
    echo "manifest-toolchain: $name drift — manifest='$want' live='$got'" >&2
    fail=1
  fi
}
check rustc "$want_rustc" "$got_rustc"
check wasm_bindgen "$want_wb" "$got_wb"
if [ "$want_opt" != "disabled" ]; then
  echo "manifest-toolchain: wasm_opt must stay 'disabled' for byte-stability (got '$want_opt')." >&2
  fail=1
fi

if [ "$fail" -ne 0 ] && [ "$enforce" = true ]; then
  exit 1
fi
if [ "$fail" -ne 0 ]; then
  echo "manifest-toolchain: drift noted (enforcement is CI-only)."
else
  echo "manifest-toolchain: ok (rustc $want_rustc, wasm-bindgen $want_wb, wasm_opt $want_opt)."
fi
