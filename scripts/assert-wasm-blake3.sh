#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproducible-.wasm BLAKE3 assertion (arch §12.5; qf Domain 7, row #23). The .wasm is built deterministically
# (wasm-opt disabled, pinned rust 1.96.0 + wasm-bindgen =0.2.125), so its BLAKE3 is a content fingerprint: an
# un-reviewed .wasm change (a toolchain drift, a hidden non-determinism) shows up as a hash mismatch.
#
# wasm-bindgen output is only byte-stable WITHIN a pinned build environment (OS / libc), so the canonical expected
# hash is generated in the pinned CI container (SOURCE_DATE_EPOCH + deterministic strip) and committed to
# spec/vectors/wasm.blake3. Enforcement is therefore CI-only (or THOUGHTMARK_ENFORCE_WASM_HASH=1); locally — likely
# a different OS — this prints the freshly-built hash and passes, so `just ci` stays green off the canonical host.
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

WASM="packages/core/wasm/thoughtmark_wasm_bg.wasm"
EXPECTED_FILE="spec/vectors/wasm.blake3"

if [ ! -f "$WASM" ]; then
  echo "assert-wasm-blake3: $WASM not built — run 'just ci-wasm' first" >&2
  exit 1
fi

ACTUAL="$(cargo run -q -p thoughtmark-cli --bin tm -- blake3 "$WASM")"

if [ -f "$EXPECTED_FILE" ] && { [ "${CI:-}" = "true" ] || [ "${THOUGHTMARK_ENFORCE_WASM_HASH:-}" = "1" ]; }; then
  EXPECTED="$(tr -d '[:space:]' <"$EXPECTED_FILE")"
  if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "WASM BLAKE3 MISMATCH (un-reviewed .wasm change — investigate, do NOT re-bless blindly):" >&2
    echo "  built    = $ACTUAL" >&2
    echo "  expected = $EXPECTED ($EXPECTED_FILE)" >&2
    exit 1
  fi
  echo "assert-wasm-blake3: ok ($ACTUAL)"
else
  echo "assert-wasm-blake3: built .wasm BLAKE3 = $ACTUAL"
  echo "  (enforcement is CI-only against $EXPECTED_FILE; generate the canonical hash in the pinned container)"
fi
