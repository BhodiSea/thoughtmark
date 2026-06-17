#!/usr/bin/env bash
# PreToolUse hook (matcher: Bash) — the TRUE blocking gate (qf Domain 1, row 3).
# Reads the pending tool call as JSON on stdin; `exit 2` BLOCKS the command before it runs.
# CI is authoritative; this is the fast local refusal of clearly-dangerous actions.
set -uo pipefail
input="$(cat 2>/dev/null || true)"
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[ -z "$cmd" ] && exit 0

block() { echo "guard-bash: BLOCKED — $1" >&2; exit 2; }

# Force-push / history rewrite to a protected branch
printf '%s' "$cmd" | grep -Eq 'git[[:space:]]+push([[:space:]].*)?(--force|--force-with-lease|-f)\b' \
  && block "force-push is forbidden (immutable signed history)"
# Pipe a remote download straight into a shell (curl … | sh)
printf '%s' "$cmd" | grep -Eq '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh)\b' \
  && block "piping a download into a shell is forbidden"
# Mutating writes to protected guardrail files (a human must review these — see CODEOWNERS)
printf '%s' "$cmd" | grep -Eq '(>|>>|[[:space:]]tee[[:space:]]|sed[[:space:]]+-i|[[:space:]]rm[[:space:]]|[[:space:]]mv[[:space:]]|[[:space:]]cp[[:space:]])[^&]*(\.claude/|\.github/|deny\.toml|rust-toolchain\.toml|clippy\.toml|CODEOWNERS)' \
  && block "edits to protected guardrail files (.claude/, .github/, deny.toml, rust-toolchain.toml, clippy.toml) require a human"

exit 0
