#!/usr/bin/env bash
# Pre-commit hook: run this repo's no-API-key static checks against the
# working tree before a commit is allowed through.
#
# Fast by design — luau-scan runs in about a second and agents.cli scan is
# plain regex/AST over the files it discovers, so this belongs in a
# pre-commit hook rather than an agent invocation (no network, no model
# call, no API key required).
#
# Install (from the target project's repo root, with this `agents` repo
# checked out and installed — `pip install -e ~/agents`):
#
#   cp ~/agents/scripts/pre-commit-agents-scan.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or, if the project uses the `pre-commit` framework, see
# docs/pre-commit-and-ci.md in this repo for a `.pre-commit-config.yaml`
# entry that calls this same script instead of copying it in.
#
# Configuration (env vars, all optional):
#   AGENTS_SCAN_FAIL_ON   Severity threshold that blocks the commit.
#                          One of CRITICAL, HIGH, MEDIUM, LOW, never.
#                          Default: HIGH.
#   SKIP_AGENTS_SCAN=1     Skip this hook entirely for one commit
#                          (e.g. `SKIP_AGENTS_SCAN=1 git commit ...`).
#
# This hook is opt-in by design — it does nothing until you install it,
# and even then it only blocks a commit once you're comfortable with what
# it finds. Run it manually a few times first (`python -m agents.cli scan
# --path .`) before wiring it in if you haven't used this scanner on this
# project before.

set -euo pipefail

if [[ "${SKIP_AGENTS_SCAN:-0}" == "1" ]]; then
  echo "agents-scan: skipped (SKIP_AGENTS_SCAN=1)"
  exit 0
fi

if ! python -m agents.cli list >/dev/null 2>&1; then
  echo "agents-scan: 'agents' package not installed in this environment (pip install -e ~/agents) — skipping" >&2
  exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
FAIL_ON="${AGENTS_SCAN_FAIL_ON:-HIGH}"

STAGED_LUAU=$(git diff --cached --name-only --diff-filter=ACM -- '*.lua' '*.luau' || true)

STATUS=0

if [[ -n "$STAGED_LUAU" ]]; then
  echo "agents-scan: running luau-scan (Luau files staged)"
  if ! python -m agents.cli luau-scan "$REPO_ROOT" --fail-on "$FAIL_ON"; then
    STATUS=1
  fi
fi

echo "agents-scan: running scan (fail-on=$FAIL_ON)"
if ! python -m agents.cli scan --path "$REPO_ROOT" --no-record --fail-on "$FAIL_ON"; then
  STATUS=1
fi

if [[ "$STATUS" -ne 0 ]]; then
  echo ""
  echo "agents-scan: blocked commit — findings at or above $FAIL_ON severity above."
  echo "Fix them, or if a finding is a false positive, dismiss it:"
  echo "  python -m agents.cli feedback <agf_id> dismiss --reason \"...\""
  echo "To bypass this one commit: SKIP_AGENTS_SCAN=1 git commit ..."
fi

exit "$STATUS"
