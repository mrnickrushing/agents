# Wiring `agents.cli scan` into pre-commit and CI

This repo's `scan` and `luau-scan` commands are plain Python/regex/AST — no
API key, no model call, no network — so they're cheap enough to run on
every commit or every PR. They were deliberately **not** wired in
automatically anywhere (see `TODO.md`): doing that changes a project's
merge gate, and that's a decision the project's own maintainer should make,
not something this toolkit should impose by default.

Both integration points below are opt-in, and both default to **report
mode** (never blocks anything) until you explicitly turn on `--fail-on`.
Try that progression in order — don't jump straight to a blocking gate on
a project you haven't scanned before.

## Before wiring in anything

Run it manually a few times first:

```fish
pip install -e ~/agents   # once, so it resolves from any repo
cd ~/your-project
python -m agents.cli scan --path .
```

Read the report, dismiss anything that's a false positive
(`python -m agents.cli feedback <agf_id> dismiss --reason "..."`), and get
a feel for what it flags on *this* project before making it automatic.

## Local pre-commit hook

`scripts/pre-commit-agents-scan.sh` in this repo runs `luau-scan` (if any
`.lua`/`.luau` files are staged) and `scan` against the working tree, and
blocks the commit only if `--fail-on` finds something.

**Plain git hook** (no extra tooling):

```fish
cp ~/agents/scripts/pre-commit-agents-scan.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Using the [pre-commit](https://pre-commit.com) framework instead**, add
to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: agents-scan
        name: agents.cli scan
        entry: bash -c 'AGENTS_SCAN_FAIL_ON=${AGENTS_SCAN_FAIL_ON:-never} ~/agents/scripts/pre-commit-agents-scan.sh'
        language: system
        pass_filenames: false
```

Both forms respect two env vars:

- `AGENTS_SCAN_FAIL_ON` — severity threshold that blocks the commit
  (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`never`). Default `never` — installing
  the hook does not, by itself, block anything.
- `SKIP_AGENTS_SCAN=1` — skip the hook for one commit
  (`SKIP_AGENTS_SCAN=1 git commit ...`).

The hook deliberately runs `scan` *without* `--no-record`: recording is
what applies previously-learned feedback
(`python -m agents.cli feedback <agf_id> dismiss --reason "..."`) before
the fail-on check runs, on the assumption that `~/.local/state/rushingtech-agents/evolution.db`
persists on your machine between commits. If you point `--db`/`AGENTS_EVOLUTION_DB`
somewhere ephemeral, dismissed findings won't stay dismissed locally either.

## CI (GitHub Actions)

`.github/workflows/agents-scan.yml` in this repo is a reusable workflow.
Call it from the target project's own workflow file:

```yaml
# .github/workflows/agents-scan.yml
name: agents-scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    uses: mrnickrushing/agents/.github/workflows/agents-scan.yml@main
    with:
      fail-on: never   # start here; switch to HIGH once you trust the findings
    secrets: inherit   # only needed if you want LLM triage via ANTHROPIC_API_KEY
```

The job caches the evolution DB across runs (keyed on the calling
repository) so a finding dismissed via `agents.cli feedback ... dismiss` —
whether recorded in an earlier CI run or synced in from local — stays
dismissed in later CI runs too, instead of every run starting from a blank
slate and re-flagging it. `luau-scan` has no `CRITICAL` severity, so the
workflow maps a `CRITICAL` threshold to `never` for that specific check
(it structurally cannot produce a `CRITICAL` finding, so nothing would
ever trip at that threshold anyway) rather than passing an argument
`luau-scan` would reject.

The job always uploads the full JSON report as a build artifact
(`agents-scan-report`), even in report-only mode — so findings are visible
in the Actions UI whether or not the job is gating anything yet.

## Turning on the gate

Once you're comfortable with what a project's scan reports:

- Local: set `AGENTS_SCAN_FAIL_ON=HIGH` (or stricter) as a persistent env
  var (the hook's own default is `never`, so this is a deliberate step).
- CI: change the workflow's `fail-on: never` to `fail-on: HIGH` (or your
  chosen threshold).

Findings dismissed via triage or via `agents.cli feedback ... dismiss` are
excluded from the fail-on check per finding, not per file — if one finding
in a file is dismissed and another in the same file is still active, the
active one still blocks even though the dismissed one doesn't.
