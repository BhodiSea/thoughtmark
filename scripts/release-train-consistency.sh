#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# release-train-consistency (arch §13.4 / §16; qf Domain 5). Refuses a PR that MUTATES (or deletes) an existing
# `spec/vectors/**` expected-byte file unless it ALSO (a) MAJOR-bumps `spec/vectors/VERSION` and (b) introduces a
# NEW format-identifier value. ADDING new vectors is always allowed (additive MINOR). This keeps the three
# version axes (code SemVer, corpus SemVer, format identifiers) from being silently conflated: changing a hashed
# byte is simultaneously a new `canon_version`-style value + a MAJOR corpus release (add canon_v2, never mutate
# canon_v1; an unknown version fails closed).
#
# Usage: scripts/release-train-consistency.sh [BASE_REF]   (BASE_REF defaults to origin/main)
set -euo pipefail
BASE="${1:-origin/main}"
VECDIR="spec/vectors"

# The frozen format-identifier value families (arch §14.2). A byte change demands a NEW one of these.
FORMAT_IDS='tm-jcs-|application/vnd\.thoughtmark\.bundle\.v|thoughtmark\.dev/Provenance/v'
# Expected-output file extensions whose CONTENT mutation is a breaking corpus event (inputs are exempt).
EXPECTED_RE='/(expected[^/]*|.*\.(bin|hex)|ok\.txt|expected_code\.txt|result\.json)$'

# Files under spec/vectors that were MODIFIED or DELETED vs base, restricted to expected-output payloads.
changed="$(git diff --name-only --diff-filter=MD "$BASE" -- "$VECDIR" \
          | grep -E "$EXPECTED_RE" \
          | grep -vE '(manifest\.json|VERSION|CHANGELOG\.md)$' || true)"

if [ -z "$changed" ]; then
  echo "release-train-consistency: ok (no existing expected byte mutated or deleted)."
  exit 0
fi

echo "release-train-consistency: existing expected outputs MUTATED/DELETED:" >&2
printf '  %s\n' "$changed" >&2

# (a) VERSION must be MAJOR-bumped.
old_ver="$(git show "$BASE:$VECDIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo '0.0.0')"
new_ver="$(tr -d '[:space:]' <"$VECDIR/VERSION")"
old_major="${old_ver%%.*}"
new_major="${new_ver%%.*}"
if [ "${new_major:-0}" -le "${old_major:-0}" ]; then
  echo "FAIL: expected bytes changed but VERSION major was not bumped ($old_ver -> $new_ver)." >&2
  exit 1
fi

# (b) a NEW format-identifier value must appear in the manifest diff (present now, absent at base).
base_ids="$(git show "$BASE:$VECDIR/manifest.json" 2>/dev/null \
            | grep -oE "($FORMAT_IDS)[A-Za-z0-9._+-]+" | sort -u || true)"
new_ids="$(git diff "$BASE" -- "$VECDIR/manifest.json" \
          | grep -E '^\+' | grep -oE "($FORMAT_IDS)[A-Za-z0-9._+-]+" \
          | sort -u | grep -vFx "$base_ids" || true)"
if [ -z "$new_ids" ]; then
  echo "FAIL: expected bytes changed without introducing a NEW format-identifier value (e.g. tm-jcs-2)." >&2
  echo "      arch §16: add canon_v2, never mutate canon_v1; an unknown version FAILS CLOSED." >&2
  exit 1
fi
echo "release-train-consistency: ok (MAJOR bump $old_ver -> $new_ver + new format id: $new_ids)."
