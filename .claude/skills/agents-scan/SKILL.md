---
name: agents-scan
description: Run this repo's no-API-key static scanner (python -m agents.cli scan / luau-scan) against a project and turn the JSON report into a readable summary. Use when the user asks to scan, audit, or check a project for security/quality issues without spinning up an LLM agent, when they mention "agents.cli", "luau-scan", or this repo's evolution/feedback loop, or when they want a fast pre-commit/CI-style pass before a deeper review.
---

# agents-scan

This repo (`rushingtech-agents`) ships two deterministic, no-API-key checkers that are plain Python/regex/AST — not LLM calls — so they're fast, free, and safe to run automatically:

- `python -m agents.cli scan --path <project>` — general project scan. Auto-discovers relevant files and routes them through the review-capable agents (security, auth, billing, mobile, API, database, infra, deployment, code quality, accessibility).
- `python -m agents.cli luau-scan <path>` — Roblox/Luau-specific static analysis (18 rules, see this repo's README). Use for any project containing `.lua`/`.luau` files or a `*.project.json` (Rojo).

Both require the package installed once per environment: `pip install -e ~/agents` (or wherever this repo is checked out), then they resolve as `python -m agents.cli ...` from any project directory.

## Deciding which to run

- Project has `.lua`/`.luau` files or a Rojo `*.project.json` → run `luau-scan`.
- Everything else (Node/Express, Python/FastAPI, React, Expo, etc.) → run `scan`.
- A project can legitimately need both (e.g. a game studio's backend + the game client) — run each against the relevant subtree.

## Running `scan`

```fish
python -m agents.cli scan --path <project>                       # human-readable
python -m agents.cli scan --path <project> --out report.json     # also write JSON
python -m agents.cli scan --path <project> --agents security_audit,auth_security   # limit scope
python -m agents.cli scan --path <project> --no-triage            # skip the LLM triage pass
python -m agents.cli scan --path <project> --no-record            # don't persist to the evolution DB
```

Notes:
- If `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set in the environment, a second-pass LLM triage runs automatically to confirm/dismiss each heuristic finding (it can read other project files to check things like "is this token's expiry actually enforced somewhere else"). Pass `--no-triage` to keep it purely heuristic, or `--triage` to force it on.
- `--runtime` additionally executes the project's own `npm test` script (or an explicit `--runtime-command`) with no shell. **This runs project code — never pass `--runtime` without the user's explicit go-ahead**, the same as you would not run arbitrary project test/build scripts unprompted.
- Every scan is recorded by default to `~/.local/state/rushingtech-agents/evolution.db` (findings + verdicts, not source contents). Use `--no-record` for a throwaway/CI run, or `--db <path>` to point elsewhere.

### Reading the report

The report's `coverage` object is the trust boundary — don't treat a clean run as "no issues found" without checking it:
- `tool_errors` should be `0`.
- `skipped_files` / `verification_gaps` should be empty — if not, say explicitly what wasn't checked and why.
- `agents_not_applicable` and `files_without_targeted_checks` explain what this scan structurally cannot see.
- A zero-finding run is labeled `static-clean-runtime-unverified` unless `--runtime` was used — report it as "static analysis found nothing," not as "this project is secure." Static analysis (and even a passing test run) cannot prove the absence of integration, environment, or product-logic bugs.

Findings triaged as dismissed false positives are kept in a "Dismissed as false positives by triage" section with the model's reasoning — summarize the confirmed findings first, but mention dismissed ones exist and why, rather than hiding that a triage pass happened.

## The evolution/feedback loop

Every finding gets a stable `agf_*` ID (tied to the exact source revision — an edit to the reviewed lines invalidates the ID and requires a fresh decision). If the user tells you a finding is wrong or already handled, record that instead of just remembering it for this conversation:

```fish
python -m agents.cli feedback agf_0123456789abcdefabcd dismiss --reason "Auth is enforced by router middleware"
python -m agents.cli feedback agf_fedcba9876543210abcd confirm --reason "Reproduced against the unauthenticated endpoint"
```

Human feedback outranks LLM triage and is applied automatically on the next scan of unchanged code, with the verdict shown as `learned:` evidence rather than silently suppressed. To see detector quality over time: `python -m agents.cli history --project <path>` and `python -m agents.cli eval --project <path>` (reports actionable precision and triage agreement — it does not claim recall, since that needs a labeled corpus this repo doesn't assume you have).

## Running `luau-scan`

```fish
python -m agents.cli luau-scan <path>                    # human-readable
python -m agents.cli luau-scan <path> --json              # machine-readable
python -m agents.cli luau-scan <path> --fail-on HIGH      # CI gate (this is the default)
python -m agents.cli luau-scan <path> --rules call_arity unresolved_requires   # subset of rules
```

This one runs in about a second, has no network/model dependency, and was specifically designed to have a very low false-positive rate (rules decline to report when they can't be sure, rather than flagging speculatively) — treat its findings as high-confidence rather than something that needs a second triage pass.

## Wiring into pre-commit / CI

If the user wants this run automatically rather than on-demand, see `docs/pre-commit-and-ci.md` in this repo for a ready-to-drop-in pre-commit hook and GitHub Actions job — don't hand-roll a different mechanism.

## Presenting results

- Lead with the highest-severity confirmed findings, file:line first.
- Always state the coverage caveats (skipped files, `not_requested` runtime status, agents not applicable) before any "looks clean" claim.
- If the user wants fixes applied, treat each finding as a normal code-review finding: fix it in the repo, don't just paste the report back at them.
