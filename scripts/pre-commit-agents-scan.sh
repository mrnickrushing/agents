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
#                          Default: never (report-only — installing this
#                          hook does not, by itself, block any commit;
#                          see docs/pre-commit-and-ci.md before setting
#                          this to a blocking value).
#   SKIP_AGENTS_SCAN=1     Skip this hook entirely for one commit
#                          (e.g. `SKIP_AGENTS_SCAN=1 git commit ...`).
#
# This hook is opt-in by design — it does nothing until you install it,
# and its default threshold never blocks a commit. Run it manually a few
# times first (`python -m agents.cli scan --path .`), get comfortable
# with what it finds and dismiss any false positives, before setting
# AGENTS_SCAN_FAIL_ON to a value that can actually block a commit.

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
FAIL_ON="${AGENTS_SCAN_FAIL_ON:-never}"

# luau-scan has no CRITICAL severity (its rules top out at HIGH), so it
# cannot accept --fail-on CRITICAL as a value. A CRITICAL threshold means
# "only block on CRITICAL", and luau-scan can never produce one — so the
# correct translation is "never block from this check", not an error.
LUAU_FAIL_ON="$FAIL_ON"
if [[ "$LUAU_FAIL_ON" == "CRITICAL" ]]; then
  LUAU_FAIL_ON="never"
fi

STAGED_LUAU=$(git diff --cached --name-only --diff-filter=ACM -- '*.lua' '*.luau' || true)

STATUS=0

if [[ -n "$STAGED_LUAU" ]]; then
  echo "agents-scan: running luau-scan (Luau files staged)"
  if ! python -m agents.cli luau-scan "$REPO_ROOT" --fail-on "$LUAU_FAIL_ON"; then
    STATUS=1
  fi
fi

# Deliberately NOT using --no-record here: recording is what applies
# previously-learned feedback (agents.cli feedback ... dismiss) to this
# scan before the fail-on check runs. With --no-record, a finding you
# already dismissed as a false positive would keep blocking every commit
# — the documented escape hatch below would not actually work.
echo "agents-scan: running scan (fail-on=$FAIL_ON)"
if ! python -m agents.cli scan --path "$REPO_ROOT" --fail-on "$FAIL_ON"; then
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
