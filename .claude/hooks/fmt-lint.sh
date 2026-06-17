#!/usr/bin/env bash
# PostToolUse hook (matcher: Edit|Write) — advisory auto-format (qf Domain 1, row 3).
# Runs AFTER the tool, so it cannot roll back; it formats the touched file and surfaces issues.
set -uo pipefail
input="$(cat 2>/dev/null || true)"
file="$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null || true)"
[ -z "$file" ] || [ ! -f "$file" ] && exit 0
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" 2>/dev/null || true
case "$file" in
  *.rs)                    command -v rustfmt >/dev/null 2>&1 && rustfmt --edition 2024 "$file" >/dev/null 2>&1 || true ;;
  *.ts|*.tsx|*.js|*.json)  command -v pnpm    >/dev/null 2>&1 && pnpm exec biome format --write "$file" >/dev/null 2>&1 || true ;;
  *.toml)                  command -v taplo   >/dev/null 2>&1 && taplo fmt "$file" >/dev/null 2>&1 || true ;;
esac
exit 0
