#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPEC.md requirement-ID <-> spec/vectors traceability (row 24). FAILS if any vector cites a requirement ID that
# SPEC.md does not define. Reports (non-fatal, Phase 0) requirements that have no vector yet — the reverse
# direction tightens as logic lands.
set -euo pipefail
SPEC="spec/SPEC.md"
VECDIR="spec/vectors"
areas='CANON|HASH|CID|SIG|LOG|CORE|SCHEMA|BUNDLE'

defined="$(grep -hoE "\\b($areas)-[0-9]+\\b" "$SPEC" | sort -u)"
used="$(grep -rhoE '"spec_req"[[:space:]]*:[[:space:]]*"[^"]+"' "$VECDIR" \
        | grep -oE "($areas)-[0-9]+" | sort -u)"

undefined="$(comm -13 <(printf '%s\n' "$defined") <(printf '%s\n' "$used") || true)"
if [ -n "$undefined" ]; then
  echo "TRACEABILITY VIOLATION: vectors cite requirement IDs not defined in $SPEC:" >&2
  printf '  %s\n' "$undefined" >&2
  exit 1
fi
echo "ok: every vector's spec_req is defined in $SPEC."

untested="$(comm -23 <(printf '%s\n' "$defined") <(printf '%s\n' "$used") || true)"
if [ -n "$untested" ]; then
  echo "note: requirements without a vector yet (tighten as logic lands):"
  printf '  %s\n' "$untested"
fi
