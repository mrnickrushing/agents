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
        entry: bash -c 'AGENTS_SCAN_FAIL_ON=${AGENTS_SCAN_FAIL_ON:-HIGH} ~/agents/scripts/pre-commit-agents-scan.sh'
        language: system
        pass_filenames: false
```

Both forms respect two env vars:

- `AGENTS_SCAN_FAIL_ON` — severity threshold that blocks the commit
  (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`never`). Default `HIGH`.
- `SKIP_AGENTS_SCAN=1` — skip the hook for one commit
  (`SKIP_AGENTS_SCAN=1 git commit ...`).

## CI (GitHub Actions)

`ci-templates/agents-scan.yml` is a reusable workflow. Call it from the
target project's own workflow file:

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

(To actually expose this file as a reusable workflow from this repo rather
than only as a copyable template, it also needs to live under this repo's
own `.github/workflows/`. See the note in `ci-templates/agents-scan.yml`
if you'd rather just copy the job into the target project directly instead
of calling back into this repo.)

The job always uploads the full JSON report as a build artifact
(`agents-scan-report`), even in report-only mode — so findings are visible
in the Actions UI whether or not the job is gating anything yet.

## Turning on the gate

Once you're comfortable with what a project's scan reports:

- Local: set `AGENTS_SCAN_FAIL_ON=HIGH` (or stricter) as a persistent env
  var, or just leave the hook script's default.
- CI: change the workflow's `fail-on: never` to `fail-on: HIGH` (or your
  chosen threshold).

Findings dismissed via triage or via `agents.cli feedback ... dismiss` are
excluded from the fail-on check automatically — only active
(non-dismissed) findings at or above the threshold block anything.
