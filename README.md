# RushingTech Agents

**AI agents for solo full-stack operators with OpenAI & Anthropic (Claude) support.**

Twelve specialized agents (73 tools total) that understand your exact stack — React/Node/Express, FastAPI, React Native/Expo, Stripe, Railway, EAS/Codemagic, Helmet, Roblox/Luau, and security-hardened everything. Dual-provider support, Claude-powered UI component generation, and a no-API-key CLI for running the underlying checks directly.

Built for the workflow at [Rushing Technologies](https://rushingtechnologies.com) — one person, every layer, real software that ships.

## 🆕 Version 2.12.0 — `agents fix`, and cheaper triage

**`agents fix`** applies the findings that are mechanical — the ones with
exactly one correct fix that is the same fix everywhere:

- **Pin actions** to the SHA their tag points at, tag kept as a comment so
  dependabot maintains the pin. A tag that cannot be resolved is left alone
  and reported: rewriting it to a guess would break the workflow while
  looking like a security improvement.
- **Scope workflow tokens** — a least-privilege top-level `permissions:` for
  workflows that have none, plus `security-events: write` on any job that
  uploads SARIF. That second half is not optional; without it, restricting
  the token turns a passing security scan into a failing one.
- **Document env vars** the code reads but `.env.example` never mentions —
  the "works locally, dies on deploy" failure, caught before the deploy.
- **Harden compose** — database ports to loopback, stock passwords
  parameterized with today's literal as the default, so local behaviour is
  unchanged and the file simply stops being reusable with a real password.

Dry run is the default and writes nothing; `--apply` re-validates every
workflow afterwards and exits non-zero if the YAML no longer parses. Every
fixer is idempotent. This began as a throwaway script that hardened fifteen
repositories in one pass (156 actions pinned, 21 tokens scoped, ~90 env
vars documented) and earns a place here because the rule behind most of
that work, `config_audit.audit_workflow`, scores **100% precision** against
recorded verdicts.

Deliberately absent: Dockerfile `USER` fixes. Each needs a judgment about
what the runtime writes and where its toolchains cache — Playwright installs
browsers into the invoking user's home, so adding `USER app` without first
pinning `PLAYWRIGHT_BROWSERS_PATH` produces an image that builds and then
fails at runtime. A fixer right nine times in ten is worse than none.

**Triage now costs one call per file, not one per finding — and the cost was
quadratic, not linear.** Findings within an entry share a file and a rule,
so they are judged together. The old loop made one call per finding *and*
keyed the conversation by file+tool, so BaseAgent's history accumulated:
finding #2 re-sent finding #1's whole prompt (file included), #3 re-sent
both, and so on. A 27-finding entry sent **378 copies of one source file**.
Across this fleet that is 775 file-copies where 299 would do. Conversations
are now also reset after every verdict — a verdict is a one-shot judgement,
not a dialogue — which additionally stops the agent holding every file it
has read in memory for the length of a run. Verdicts return as an indexed
array so a short response degrades to UNKNOWN rather than sliding verdicts
onto the wrong findings.

## 🆕 Version 2.11.0 — The scanner earns belief

**`agents precision`** — per-rule precision from every recorded verdict
(human `feedback`, the MCP's `record(kind="verdict")`, or scan-time LLM
triage). Rules with enough verdicts to mean something get scored; precision
over a handful of data points is a coin toss with a decimal, so under five
verdicts nothing is scored at all.

**`agents precision --write-trust`** — the self-correcting part. A scored
rule below 50% precision is written into a trust map that every subsequent
scan consults: its findings keep appearing (the rule might be fixed
tomorrow) but demote to INFO, carry their original severity in
`pre_demotion_severity`, and say why (`"rule precision 20% over recorded
verdicts"`). A detector that is wrong more than half the time it is judged
costs more attention than it saves — now that costs it its severity
automatically, instead of costing the operator their trust in the whole
report. First live run found one: `validate_accessibility`, 0-for-12.

## 🆕 Version 2.10.0 — Config surfaces, and a prospect-facing report

**`config_audit` — the files the code scanners never opened.** A fleet
baseline showed 368 findings and *zero* from Dockerfiles, docker-compose, 41
GitHub workflow files, 12 Android manifests, 11 plists, wrangler.toml, or
Railway config — not because they were clean, but because the text-candidate
gate never let those files reach a rule. New agent, eight checks, all pure
heuristics (no API key, so they run in CI where it matters):

- **Dockerfile**: final stage running as root, unpinned base images,
  secrets baked in via ENV/ARG, `curl | sh`.
- **docker-compose**: privileged containers, databases published to all
  interfaces, committed dev credentials.
- **Workflows**: unpinned actions (third-party graded above first-party),
  missing `permissions:`, `pull_request_target` + checkout, expression
  injection from event titles into `run:`.
- **AndroidManifest**: cleartext traffic, `debuggable`, `allowBackup`,
  exported services/receivers/providers with no permission gate. Debug-variant
  manifests are exempt — cleartext there is how Metro works.
- **Info.plist**: ATS disabled. **wrangler.toml**: secrets in `[vars]`.
- **railway config**: a `healthcheckPath` no route in the repo serves — the
  misconfiguration that burned $40/month polling a 404 every 15 minutes.
- **.env.example**: real-looking secret values committed, and env vars the
  code reads that the example never documents (the "works locally, dies on
  Railway" failure, caught before the deploy).

**Reality-corrected before shipping, per the session-12 rule.** The first
fleet run produced seven "committed secret" HIGHs — every one a placeholder
(`change-me-in-production`, `REPLACE_WITH_...`) the old pattern missed — plus
a stage alias flagged as an unpinned image, a `/ready` healthcheck flagged
because the config sat in `infra/` away from the code, and debug-manifest
cleartext flagged as if it shipped. All fixed and pinned by tests; the final
fleet pass is 129 findings (3 HIGH, 48 MEDIUM, 78 LOW) with each HIGH
verified by hand.

**`prospect_report` — a scan rendered for someone deciding whether to hire
you.** `python -m agents.prospect_report report.json --company "Acme"` groups
findings into themes with business-consequence copy. Counts are unmodified
scanner output; file paths, line numbers, and rule ids never reach the page —
the document is designed to be forwarded, and a teaser that maps every
weakness is both a free audit and a liability for the prospect. An empty scan
says "no findings" rather than padding.

## 🆕 Version 2.9.0 — Every agent reachable from Claude Code, plus opt-in CI/pre-commit gating

- **6 missing Claude Code subagent mirrors added**: `.claude/agents/` previously only mirrored 6 of the 12 Python agents. Added `auth-security-reviewer`, `api-architect`, `database-architect`, `infra-monitor`, `mobile-deploy-advisor`, and `roblox-auditor` so every domain this package covers is now reachable as a subagent inside a Claude Code session, not just from the standalone Python API/CLI.
- **`agents-scan` Claude Code skill**: wraps `agents.cli scan`/`luau-scan` so a session can run either and correctly interpret the JSON report — the `coverage` trust boundary, triage vs. learned-feedback dismissals, and the `agf_*` feedback loop — without remembering CLI flags.
- **`scan --fail-on` for CI/pre-commit gating**: `scan` now supports the same `--fail-on {CRITICAL,HIGH,MEDIUM,LOW,never}` threshold `luau-scan` already had. Default is `never` (report-only; exits 0 regardless of findings), so nothing changes for existing callers — pass e.g. `--fail-on HIGH` to make the process exit non-zero when a finding not individually dismissed by triage or learned feedback meets the threshold. The check is evaluated per finding, not per file — a file with one dismissed and one still-active finding blocks correctly on the active one alone.
- **Ready-to-adopt pre-commit hook and CI template**: `scripts/pre-commit-agents-scan.sh` (plain git hook or `pre-commit` framework) and `.github/workflows/agents-scan.yml` (reusable GitHub Actions workflow, callable via `uses:` from any project) — both opt-in and report-only (`--fail-on never`) by default until deliberately switched to a blocking threshold. See `docs/pre-commit-and-ci.md`.

## 🆕 Version 2.8.0 — Runtime-aware Roblox scans

- **Dependency-aware reproducibility gaps**: a dependency-free `package.json` no longer produces a misleading missing-lockfile warning; projects with declared dependencies still require a recognized lockfile.
- **Roblox project-script coverage**: Node validation/build scripts that spawn commands receive a dedicated safety check, so Roblox projects no longer leave `scripts/typecheck.mjs` outside specialized coverage.
- **Opt-in runtime verification**: `scan --runtime` runs the declared `npm test` script without a shell, or an explicit `--runtime-command`, and records the exit code, duration, and bounded output tail. Runtime execution is opt-in because it executes project code.

## Luau static analysis (`luau-scan`)

Deterministic whole-repository checks for any Roblox/Luau project. **No API
key, no model call, no network** — it runs in about a second, so it belongs in
a pre-commit hook or a CI step rather than an agent invocation.

```bash
pip install -e ~/agents          # once, so it resolves from any repo
cd ~/my-other-game
python -m agents.cli luau-scan .                 # human-readable
python -m agents.cli luau-scan . --json          # machine-readable
python -m agents.cli luau-scan . --fail-on HIGH  # CI gate (default)
python -m agents.cli luau-scan . --rules call_arity unresolved_requires
```

It exists because of a specific outage. A builder function gained a required
parameter, one call site was not updated, Luau passed `nil`, and the service
that owned an entire game region failed to initialize — shipping that way
through nine published versions. The test suite could not catch it: it only
asserted modules were *present* in the built place, and the type checker ran
on a platform that could not see the file.

That is not a judgement call a model should be asked to make. It is arithmetic
on argument counts, so it is done exactly instead.

| Rule | Severity | Catches |
|---|---|---|
| `call_arity` | HIGH | Call passing fewer arguments than the function requires |
| `use_before_definition` | HIGH | `local function` called above its definition (not hoisted) |
| `unresolved_require` | HIGH | `require` naming a module that no longer exists |
| `findfirstchild_nil` | HIGH | `FindFirstChild(...)` indexed with no nil check |
| `player_chatted` | HIGH | `Player.Chatted`, which never fires under TextChatService |
| `rojo_missing_path` | HIGH | `$path` pointing at a directory that does not exist |
| `rojo_server_in_client` | HIGH | Server source mapped into a client-visible service |
| `unprotected_async` | MEDIUM | Datastore/asset/teleport calls with no nearby `pcall` |
| `unanchored_part` | MEDIUM | Parts built in a file that never sets `Anchored` |
| `shadow_light_in_loop` | MEDIUM | Shadow-casting lights created in a loop (Future lighting cost) |
| `connection_leak` | MEDIUM | Per-frame connection whose handle is discarded |
| `per_frame_allocation` | MEDIUM | `GetChildren`/`GetDescendants` inside a frame callback |
| `gameplay_clock` | MEDIUM | `os.time()`/`tick()` used for timing that crosses the network |
| `deprecated_api` | MEDIUM | `:Remove()`, and `Instance.new` parenting before properties |
| `rojo_lighting_unset` | MEDIUM | `Lighting.Technology` never declared (unsettable from script) |
| `unread_definition_field` | MEDIUM | Authored content fields nothing ever reads |
| `deprecated_scheduler` | LOW | `wait`/`spawn`/`delay` globals |
| `missing_strict_mode` | LOW | Type annotations without `--!strict` |
| `scattered_asset_ids` | LOW | Inline `rbxassetid` literals outside a registry |

On its first run against a 153-file production game it reported **13 findings
of which 12 were false positives** — a method named `spawn`, throttled frame
callbacks, a type schema read as content, startup connections read as leaks,
and a deliberate legacy-chat fallback. All five rules were tightened and the
shapes kept as regression tests. It now reports 3, all genuine.

**Precision is the design constraint, not coverage.** A checker that cries
wolf gets muted, and muting takes the working rules down with it — so every
rule declines to report when it cannot be sure. Each one is tested twice:
once that it fires on a real defect, once that it stays silent on correct
code. On a 153-file production game it reports 13 findings, and the first
version of the connection rule flagged fourteen correct call sites before
being tightened.

The same checks are available to `RobloxAuditAgent` as the
`scan_repository_statically` tool.

## 🆕 Version 2.7.0 — Roblox/Luau coverage expansion

Grounded against Roblox's own Creator Hub docs (security tactics, DataStore request-budget limits, TextService/TextChatService filtering, MarketplaceService purchase flows) rather than assumption, plus a fix for a stripping bug the new checks exposed.

- **Two new checks**: `audit_text_filtering` catches a remote handler that re-broadcasts a textual-looking argument (`FireAllClients`/`FireClient`) with no `TextService`/`TextChatService` filtering call — unfiltered player-authored text reaching other players violates Roblox's content policy. `audit_admin_backdoor` catches privileged/admin access gated by comparing `player.Name`/`player.DisplayName` to a hardcoded string instead of `player.UserId` — `DisplayName` is entirely player-chosen, and there are real incidents of someone renaming themselves to match a name-based owner check and getting full admin.
- **`audit_datastore_usage` now catches request-budget risk**: a DataStore call inside a loop over many players/keys with no `GetRequestBudgetForRequestType` check or `task.wait` stagger — the request budget is shared per experience across every server, so one server bursting past it throttles saves everywhere.
- **`review_receipt_processing` now catches Developer Product grants issued from `PromptProductPurchaseFinished`** instead of `ProcessReceipt` — Roblox's own guidance is explicit that the prompt-finished event only reflects UI closure, not a confirmed backend transaction, so granting there can pay out a purchase that later fails or miss one that settles after the prompt closes. (Game Passes are different — `PromptGamePassPurchaseFinished` + a rejoin-time `UserOwnsGamePassAsync` check is the correct pattern for those, and isn't flagged.)
- **`audit_performance_patterns` now catches `FindFirstChild("literal")` inside a per-frame connection**, the same caching gap as the existing `game:GetService(` check.
- **Bug fix**: the Luau noise-stripper used by every block-boundary check was deleting string literals *including their quote characters*, so any check that needs to know a literal is present (not just absent-of-comment-noise) — the new admin-backdoor and FindFirstChild checks — could never match. String literals now collapse to an empty `""`/`''` instead of disappearing outright.

## 🆕 Version 2.6.0 — Roblox/Luau support

- **🎮 Roblox Audit Agent**: the first non-web/mobile agent in this project. Reviews Roblox/Luau source and Rojo project files for the exploit surface that's specific to Roblox — RemoteEvent/RemoteFunction handlers that trust client-supplied player identity instead of the engine-trusted sender argument, missing input validation/rate limiting, client-side writes to authoritative state (leaderstats, DataStore), a Rojo `*.project.json` tree that maps server-only source into a client-visible service (ReplicatedStorage, StarterPlayer, StarterGui, StarterPack, Workspace, ReplicatedFirst) where any exploiter can read it, DataStore calls missing pcall/xpcall or a `BindToClose` save, a `GetAsync`+`SetAsync` read-modify-write race that should be `UpdateAsync`, signal `:Connect(` leaks (a per-frame RunService signal nested in `PlayerAdded`/`CharacterAdded` with no `:Disconnect(` anywhere, or a connection made inside a loop body), deprecated `wait()`/`spawn()`/`delay()`, an unyielding `while true do`, and `MarketplaceService.ProcessReceipt` callbacks missing the required `Enum.ProductPurchaseDecision` return, `PurchaseId` idempotency, or a pcall-wrapped grant.
- **Real Lua block boundaries, not character windows**: every other agent's "is X inside Y" checks use a fixed character window after the trigger, which is good enough for JS/Python's brace- and indentation-heavy style but silently misjudged Lua's `do`/`if`/`function`/`repeat` ... `end`/`until` blocks (initial windowed drafts of this agent both missed a real bug placed just past the window and, in the other direction, flagged code that ran *after* a loop as if it were still inside it). `roblox_audit` walks real block-opening/closing keywords with a stack to find the exact boundary instead of guessing a window size.
- **CLI scan support**: `.lua`/`.luau` are now recognized code extensions and `*.project.json` triggers the Rojo structure check, so `agents.cli scan --path ~/your-roblox-game` picks these up automatically alongside the existing agents. Wally's `Packages`/`DevPackages`/`ServerPackages` dependency output is excluded the same way `node_modules` is.

## 🧠 Version 2.5.0 — Agents That Learn

- **Persistent scan history**: every scan is recorded in a local SQLite database with the detector version, project identity, findings, and triage evidence.
- **Stable, revision-aware finding IDs**: the same finding in unchanged source keeps the same `agf_*` ID. Editing the reviewed file changes the ID, preventing an old dismissal from suppressing changed code.
- **Human feedback loop**: confirm or dismiss a finding once and that verdict is applied to future scans of the same revision. Human decisions outrank model triage, and learned decisions remain visible in reports.
- **Measurable quality**: `agents eval` reports labeled findings, actionable precision, per-detector outcomes, and LLM triage agreement. Recall is deliberately not invented from scan feedback; the report explains when a labeled clean-file corpus is required.
- **Safe evolution boundary**: agents learn project-specific verdicts automatically, but never rewrite or promote their own detector code. Detector changes still go through tests, review, and version control.

## 🆕 Version 2.4.0 — What's New

- **One-shot scan restored and broadened**: `scan` now routes project evidence through all ten review-capable agents across security, auth, billing, mobile, API, database, infrastructure, deployment, code, and accessibility. The scaffolder is reported explicitly as generation-only instead of being silently omitted.
- **Evidence-backed completeness contract**: every report records checks run, agents exercised/not applicable, skipped or unreadable files, detector failures, untested code, missing CI/lockfiles, and files with no targeted rule. A zero-finding scan is labeled `static-clean-runtime-unverified`; skipped files or detector failures make it `incomplete`.
- **High-confidence project integrity checks**: Python syntax, strict JSON syntax, and unresolved merge-conflict markers run independently of framework discovery.
- **Cross-file and project-level context**: local wrappers are followed for pagination, health checks, error boundaries, and RevenueCat; Express 5 and `express-async-errors` are recognized at the workspace level.
- **Lower false-positive rate**: discovery ignores API names in comments and strings, generated `dist-*`/`build-*` trees and test implementations are excluded from behavioral review, and JWT, APNs, RevenueCat, billing receipt, migration, N+1, accessibility, and async-route checks use narrower evidence.
- **Per-finding LLM triage**: each candidate is confirmed or dismissed independently, so one real bug no longer forces every other finding in the same file to remain active.

## 🆕 Version 2.3.0 — What's New

- **🔬 LLM triage for `scan`**: the heuristic checks are fast and free but can't see outside the one file they're looking at, so a decent share of what they flag turns out to be handled correctly in a different file (a nonce hashed client-side and verified server-side, a token whose expiration is enforced by the layer that issues it rather than the layer that only verifies it, etc.). `scan` now automatically runs a second-pass triage over its own findings with a real model — one that can read other project files via a `read_project_file` tool before deciding — whenever `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set. No key set → nothing changes, still fully heuristic. See `agents/triage.py` and `--triage`/`--no-triage` below.

## 🆕 Version 2.2.0 — What's New

- **🌐 API Architect Agent**: pagination affordances, error response shape consistency, status code correctness, OpenAPI stub generation
- **🗄️ Database Architect Agent**: index coverage on FK columns, migration safety against populated tables (Alembic + raw SQL), N+1 query detection, missing unique constraints
- **📈 Infra Monitor Agent**: Sentry setup review (DSN handling, sampling, PII), health-check depth (does it verify the DB, or just return 200?), error boundary coverage, alert rule design
- **🔎 6 new SecurityAuditAgent checks**: `audit_sql_injection`, `audit_xss_patterns`, `audit_csrf_protection`, `audit_input_validation`, `audit_file_upload`, `audit_websocket_auth` — these were listed in earlier docs but never actually implemented; now real and validated against production code
- **CodeReviewAgent's existing tools wired into `cli.py scan`** — `review_express_route`, `review_react_component`, `review_drizzle_schema`, `review_zod_validation`, `review_expo_integration` now actually run as part of a scan instead of sitting unused
- **More heuristic accuracy fixes found during this pass**: a case-mismatch bug that made the push-notification permission check fire 100% of the time regardless of whether permissions were requested; `expo` matching inside "export"; SQL-injection keyword matching bare English words ("update" in a sentence); a JS-route reviewer (`review_express_route`) firing on Python/FastAPI files because `@router.get(...)` coincidentally contains the same substring as Express's `router.get(`, telling Python code to "add Zod validation"

## 🆕 Version 2.1.0 — What's New

- **🔐 Auth Security Agent**: JWT refresh rotation, Apple Sign-In (nonce/JWKS/audience), Google OAuth, shared-secret app gates, biometric auth
- **📱 Mobile Deploy Agent**: EAS build config (incl. hardcoded-secret detection), Codemagic workflows, App Store/Play submission checklists, RevenueCat setup
- **🖥️ CLI**: `python -m agents.cli` calls the deterministic tool handlers directly — no LLM API key needed. `scan` auto-discovers relevant files in a project and runs the matching checks.
- **🔁 Multi-round tool calling**: `run()` now loops on chained tool calls instead of stopping after one round trip
- **🩹 Heuristic accuracy fixes**: several checks (JWT expiry, CORS, accessibility, billing auth) previously matched on overly broad substrings (e.g. "exp" matching "express") and rarely fired — tightened across the board and validated against real code
- **🐍 Python/FastAPI awareness**: `scan_dependencies` now handles `requirements.txt`, `analyze_helmet_config` scans raw source (not just hand-built JSON), `audit_cors_config` recognizes FastAPI's `CORSMiddleware`

## The Agents

| Agent | Provider | What It Does |
|---|---|---|
| **SecurityAuditAgent** | OpenAI, Anthropic | Helmet config (incl. raw source), OWASP Top 10, JWT vulnerabilities (Node + Python), SQL injection, XSS, CSRF, file upload, WebSocket auth, dangerous-sink input validation, npm/pip dependency scanning, CORS (Express + FastAPI) |
| **AuthSecurityAgent** | OpenAI, Anthropic | JWT refresh rotation/revocation, Apple Sign-In (nonce/JWKS/issuer/audience), Google OAuth CSRF, shared-secret app gates (x-api-key), biometric auth |
| **StripeBillingAgent** | OpenAI, Anthropic | Webhook handler review, subscription model design, RevenueCat sync, billing security audit, receipt validation, dunning management, disputes, coupons, tax |
| **RailwayDeployAgent** | OpenAI, Anthropic | CI/CD workflows (GitHub Actions, Codemagic, EAS), platform configs (Vercel, Cloudflare), Sentry integration, migrations, monitoring alerts, backup strategies |
| **MobileDeployAgent** | OpenAI, Anthropic | EAS build profile review (hardcoded secrets, production hardening), Codemagic code-signing hygiene, App Store/Play submission checklists, RevenueCat SDK setup |
| **CodeReviewAgent** | OpenAI, Anthropic | Express routes, React/Expo components, Drizzle schemas, Zustand stores, Socket.io handlers, Celery tasks, API design, performance, accessibility, tests |
| **APIArchitectAgent** ⭐ NEW | OpenAI, Anthropic | Pagination affordances, error response shape consistency, status code correctness, OpenAPI stub generation |
| **DatabaseArchitectAgent** ⭐ NEW | OpenAI, Anthropic | Index coverage (Drizzle + SQLAlchemy 2.0), migration safety against populated tables, N+1 query detection, missing unique constraints |
| **InfraMonitorAgent** ⭐ NEW | OpenAI, Anthropic | Sentry setup (DSN, sampling, PII), health-check depth, React error boundary coverage, alert rule design |
| **RobloxAuditAgent** ⭐ NEW | OpenAI, Anthropic | RemoteEvent/RemoteFunction trust boundary and validation, client-side writes to authoritative state, Rojo project-structure leaks (server source shipped to clients), DataStore pcall/UpdateAsync/BindToClose/request-budget safety, connection-leak and per-frame caching detection, deprecated wait/spawn/delay and unyielding loops, MarketplaceService.ProcessReceipt/PromptProductPurchaseFinished review, TextService/TextChatService filtering gaps, Name/DisplayName-based admin backdoors |
| **ScaffolderAgent** | OpenAI, Anthropic | Project bootstrapping — Express APIs, React SPAs, Expo apps, FastAPI services, SaaS platforms, CI/CD configs |
| **UIGenerationAgent** ⭐ UPGRADED | Anthropic (Claude) | World-class UI design — design system/theme generation (color theory, type scale, motion, elevation), React/TypeScript component generation, multi-turn refinement, accessibility validation |

## CLI — use the checks without an API key

The tool handlers behind each agent are plain Python (regex/heuristic checks over a string), separate from the LLM planning loop. The CLI calls them directly:

```fish
# List every agent and its tools
python -m agents.cli list

# Run one check against a real file
python -m agents.cli run security_audit check_jwt_implementation --file code=backend/src/routes/auth.ts
python -m agents.cli run security_audit scan_dependencies --file package_json=backend/requirements.txt

# Auto-discover relevant files in a project and run the matching checks
python -m agents.cli scan --path ~/Vitality
python -m agents.cli scan --path ~/shield-ai --agents security_audit,auth_security --out report.json

# Run static checks plus an explicitly authorized project test command
python -m agents.cli scan --path ~/lastlight --runtime --no-triage --no-record
# Or provide a command when the project has no npm test script
python -m agents.cli scan --path ~/lastlight --runtime --runtime-command 'npm run test:luau' --no-triage --no-record
```

`scan` walks the project (skipping dependencies, generated output, caches, and virtual environments), matches files by name or executable evidence, runs every applicable deterministic review, and prints a severity-sorted report. Both forms are supported: `scan --path ~/project` and `scan ~/project`.

### Evolution loop — teach the agents from real outcomes

Scans are recorded by default in `~/.local/state/rushingtech-agents/evolution.db`. Only scan metadata, normalized findings, verdicts, and the report are stored—not source-file contents. Set `AGENTS_EVOLUTION_DB` or pass `--db` to choose another database; use `--no-record` for an ephemeral scan.

```fish
# Scan normally; each finding now includes a stable agf_* ID
python -m agents.cli scan --path ~/Vitality --no-triage

# Teach the system what happened
python -m agents.cli feedback agf_0123456789abcdefabcd dismiss \
  --reason "Authentication is enforced by the router middleware"
python -m agents.cli feedback agf_fedcba9876543210abcd confirm \
  --reason "Reproduced against the unauthenticated endpoint"

# Inspect history and measure detector quality
python -m agents.cli history --project ~/Vitality
python -m agents.cli eval --project ~/Vitality
```

On the next unchanged scan, prior feedback is printed as `learned:` evidence and false positives move to the auditable dismissed section. A source edit creates a new finding ID and requires a new decision. This makes learning useful without turning a stale exception into a permanent blind spot.

The evaluation output calls confirmed findings divided by all human-labeled findings **actionable precision**. It also compares model triage with human verdicts and breaks results down by detector. It does not claim recall: measuring missed findings requires a separate corpus containing known vulnerabilities and known-clean files.

The JSON report's `coverage` object is part of the result, not decoration. Before treating a clean run as meaningful, require `tool_errors: 0`, no `skipped_files`, no `verification_gaps`, and review `agents_not_applicable` plus production `files_without_targeted_checks`. Runtime execution is never implicit: without `--runtime`, `runtime_verification.status` is `not_requested`; with it, the report records the argv, exit code, duration, and bounded output tail. Static analysis and project tests still cannot prove the absence of integration, environment, Studio, or product-logic bugs; the confidence label makes that boundary explicit instead of presenting “no findings” as a guarantee.

### Triage — cut the false positives with a real model

Heuristics only ever see the one file they matched. That's enough to *find candidates* but not enough to know, say, that a file which merely verifies a JWT doesn't need to be the one setting its expiration — some other file issues the token and does that correctly. Triage re-examines every flagged file with an LLM that can pull in other project files on demand before it confirms or dismisses each finding.

```fish
# Runs automatically if ANTHROPIC_API_KEY or OPENAI_API_KEY is set — no flag needed
python -m agents.cli scan --path ~/Vitality

# Force it on/off explicitly
python -m agents.cli scan --path ~/Vitality --triage
python -m agents.cli scan --path ~/Vitality --no-triage

# Pick a provider/model
python -m agents.cli scan --path ~/Vitality --triage-provider openai --triage-model gpt-5
```

Confirmed findings stay in the main report with a `triage: CONFIRMED — <reason>` line; dismissed ones move to a "Dismissed as false positives by triage" section at the end with the model's reasoning, instead of vanishing outright — the verdict itself stays auditable. Triage evaluates each finding independently, even when one file has multiple candidates. This is opt-out-by-presence-of-key rather than a flag you have to remember: wire `agents` into a new project with an API key already in the environment (CI secret, local `.env`, whatever) and triage is just on.

## Install

```fish
# Clone and install locally
git clone https://github.com/mrnickrushing/agents.git
cd agents
pip install -e .

# Install dependencies
pip install openai>=1.0.0 anthropic>=0.40.0
```

All shell snippets below are `fish`. All `python` blocks are Python code, not shell commands, and should be run with `python` or saved to a `.py` file first.

## Quick Start

### OpenAI Provider

```python
from agents import SecurityAuditAgent

# Uses OPENAI_API_KEY from environment
agent = SecurityAuditAgent(provider="openai")

result = agent.run("Audit my Express app — Helmet CSP is disabled and CORS is set to '*'")
print(result.content)
```

### Anthropic (Claude) Provider

```python
from agents import SecurityAuditAgent

# Uses ANTHROPIC_API_KEY from environment
agent = SecurityAuditAgent(
    provider="anthropic",
    model="claude-sonnet-4-6"
)

result = agent.run("Audit this Stripe webhook handler for security issues")
print(result.content)
```

### UI Generation (Claude-Powered)

```python
from agents import UIGenerationAgent

agent = UIGenerationAgent(
    api_key="sk-ant-...",
    provider="anthropic",
    model="claude-sonnet-4-6"
)

# Single turn — create a component
result = agent.run(
    "Create a responsive dashboard card with:"
    "- Title (string prop)"
    "- Metric value (number prop)"
    "- Trend indicator ('up', 'down', 'neutral')"
    "- Sparkline chart"
    "- Dark theme support"
    "- Fully accessible"
)
print(result.content)  # Complete React component code

# Multi-turn conversation
result = agent.run(
    "Now make the card clickable with hover effects",
    conversation_id="dashboard-card-123"
)
```

### Wireframe to Component

```python
import base64

agent = UIGenerationAgent(api_key="sk-ant-...")

# Load wireframe image
with open("wireframe.png", "rb") as f:
    image_data = base64.b64encode(f.read()).decode()

# Analyze wireframe and generate component
response = agent.process_wireframe(
    description="Create a navigation bar component",
    image_base64=image_data,
    media_type="image/png",
    conversation_id="navbar-dev"
)
print(response.content)
```

## Multi-Turn Conversations

All agents support conversation history with conversation IDs:

```python
from agents import UIGenerationAgent

agent = UIGenerationAgent(api_key="sk-ant-...")
conversation_id = "my-component-v1"

# Turn 1: Create initial component
agent.run("Create a stats card", conversation_id=conversation_id)

# Turn 2: Add features
agent.run("Add a trend indicator", conversation_id=conversation_id)

# Turn 3: Apply styling
agent.run("Make it dark-themed", conversation_id=conversation_id)

# Conversation history is maintained
print(f"Messages: {len(agent.history)}")

# Reset if needed
agent.reset(conversation_id=conversation_id)
```

## Using Tools Directly (No API Key Needed)

Every agent has built-in tools you can call directly without an API key:

```python
from agents import SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent, UIGenerationAgent

# Security — analyze Helmet config
security = SecurityAuditAgent()
findings = security._tool_handlers["analyze_helmet_config"](
    config_json='{"contentSecurityPolicy": false}',
    framework="express"
)

# Billing — design subscription model
billing = StripeBillingAgent()
model = billing._tool_handlers["design_subscription_model"](
    product_name="MySaaS",
    tiers='[{"name":"Free","price_monthly":0},{"name":"Pro","price_monthly":29}]',
    mobile_iap=True,
)

# Deploy — get deployment checklist
deploy = RailwayDeployAgent()
checklist = deploy._tool_handlers["deployment_checklist"](
    project_type="saas_platform",
    platform="railway",
    has_stripe=True,
)

# UI Generation — validate accessibility
ui_agent = UIGenerationAgent()
validation = ui_agent._tool_handlers["validate_accessibility"](
    component_code="""
    <div onClick={handleClick}>
        <img src="icon.png" />
        <h4>Title</h4>
    </div>
    """,
    severity="serious"
)
print(f"Accessibility Score: {validation['overall_score']}/100")
```

## Provider Configuration

```python
from agents import SecurityAuditAgent

# OpenAI (default)
agent = SecurityAuditAgent(
    api_key="sk-...",
    provider="openai",
    model="gpt-5",
    temperature=0.3,
)

# Anthropic (Claude)
agent = SecurityAuditAgent(
    api_key="sk-ant-...",
    provider="anthropic",
    model="claude-sonnet-4-6",
    temperature=0.7,
)

# Using environment variables
# set -gx OPENAI_API_KEY "sk-..."
# set -gx ANTHROPIC_API_KEY "sk-ant-..."
agent = SecurityAuditAgent(provider="openai")  # Uses OPENAI_API_KEY
agent = SecurityAuditAgent(provider="anthropic")  # Uses ANTHROPIC_API_KEY
```

## Agent Details

### SecurityAuditAgent

**Security Domain Coverage (15 areas):**
- Helmet.js configuration analysis
- JWT implementation vulnerabilities
- Dependency scanning (npm/Python)
- CORS configuration audit
- Rate limiting review
- SQL injection detection
- XSS vulnerability audit
- CSRF token validation
- Input sanitization
- File upload security
- WebSocket auth audit
- SSL/TLS configuration
- Mobile security (iOS/Android)
- Session management
- Deployment hardening

**Key Tools:**
- `analyze_helmet_config` — Deep Helmet.js CSP and header analysis
- `check_jwt_implementation` — JWT token generation, rotation, storage audit
- `scan_dependencies` — Vulnerability scan of package.json/requirements.txt
- `audit_cors_config` — CORS wildcard detection and origin validation
- `generate_helmet_config` — Production-ready Helmet config with all headers
- `audit_rate_limiting` — Rate limiter configuration analysis
- `audit_sql_injection` — SQL injection vulnerability detection
- `audit_xss_patterns` — XSS vulnerability patterns
- `audit_csrf_protection` — CSRF token implementation review
- `audit_input_validation` — Input sanitization patterns
- `audit_file_upload` — File upload security review
- `audit_websocket_auth` — WebSocket authentication audit
- `audit_ssl_tls` — SSL/TLS configuration review
- `audit_mobile_security` — iOS/Android security patterns
- `generate_pen_test_report` — Penetration test report template

### AuthSecurityAgent ⭐ NEW

**Auth Flow Coverage:**
- JWT access/refresh rotation and reuse detection
- Apple Sign-In server-side verification (nonce, JWKS, issuer, audience)
- Google/social OAuth CSRF (state param) and token exchange security
- Shared-secret app gates (x-api-key pattern) — timing-safe comparison, no hardcoded fallback
- Biometric auth (Face ID / LocalAuthentication) — fallback and credential binding

**Key Tools:**
- `review_refresh_token_rotation` — refresh token reuse/rotation/hashing and algorithm-confusion checks
- `review_apple_sign_in` — nonce, JWKS signature verification, issuer/audience validation
- `review_oauth_flow` — CSRF state param, server-side token exchange, audience validation
- `audit_shared_secret_auth` — timing-safe comparison, hardcoded fallback detection
- `review_biometric_auth` — enrollment/fallback checks, credential binding (not a bare local gate)

### StripeBillingAgent

**Billing Lifecycle (14 areas):**
- Webhook handler security
- Subscription model design
- RevenueCat mobile-to-backend sync
- Billing security audit
- Receipt validation
- Dunning management
- Dispute handling
- Coupon/promo codes
- Metered billing
- Invoice reconciliation
- Trial lifecycle management
- Refund workflows
- Stripe Connect
- Tax compliance

**Key Tools:**
- `review_webhook_handler` — Stripe webhook security review
- `generate_webhook_handlers` — Complete webhook handler generation
- `setup_revenuecat_sync` — RevenueCat integration code
- `design_subscription_model` — Subscription tier configuration
- `audit_billing_security` — Billing security audit
- `review_receipt_validation` — Receipt validation code review
- `configure_dunning_management` — Dunning workflow setup
- `handle_dispute_responses` — Dispute response generation
- `setup_coupon_system` — Coupon configuration
- `configure_metered_billing` — Metered billing setup
- `reconcile_invoices` — Invoice reconciliation scripts
- `manage_trial_lifecycle` — Trial automation
- `configure_refund_workflow` — Refund handling configuration
- `setup_stripe_connect` — Stripe Express/Connect setup
- `configure_tax_settings` — Tax calculation and compliance

### RailwayDeployAgent

**Deployment Orchestration:**
- `diagnose_build_failure` — Railway/Vercel/Cloudflare/EAS build failure analysis from build logs
- `generate_railway_toml` — Railway deployment configuration
- `generate_docker_compose` — Docker Compose with Postgres/Redis/Celery services
- `deployment_checklist` — Pre-deployment checklist (Stripe, Sentry, CORS, rate limiting)
- `setup_env_vars` — Required environment variables for a given stack + integration set

### MobileDeployAgent ⭐ NEW

**EAS / Codemagic / App Store Readiness:**
- `review_eas_config` — flags literal secrets committed into `eas.json` build profiles, missing production hardening (autoIncrement, submit config)
- `review_codemagic_config` — code-signing hygiene (no inlined keys), trigger scoping, TestFlight/App Store submission steps
- `app_store_submission_checklist` — App Store/Play submission checklist (privacy labels, ATT, HealthKit disclosures, IAP readiness) by app category
- `review_revenuecat_setup` — Purchases.configure() timing, offerings error handling, restorePurchases(), entitlement-gated purchase flow

### CodeReviewAgent

**Code Review Domains (7 areas):**
- Express route review (security, validation, error handling)
- React component review (effects, accessibility, performance)
- Drizzle schema review (relations, constraints, indexes)
- Zod validation review (complexity, coercion, cross-field)
- Expo integration review (config, SQLite, routing)
- Stripe webhook review (security, idempotency, retries)
- Zustand store review (selectors, re-render optimization)
- Socket.io handler review (auth, rooms, Redis adapter)
- Celery task review (idempotency, retry, monitoring)
- API design review (REST conventions, error format, pagination)
- Performance review (N+1 queries, re-renders, caching)
- Accessibility review (WCAG 2.1 AA compliance)
- File upload review (validation, storage, security)
- Test suggestions (framework-specific test generation)

**Key Tools:**
- `review_express_route` — Express route handler audit
- `review_react_component` — React/React Native component review
- `review_drizzle_schema` — Drizzle ORM schema review
- `review_zod_validation` — Zod schema validation review
- `review_expo_integration` — Expo integration audit
- `review_stripe_webhook` — Stripe webhook security review
- `review_zustand_store` — Zustand state management review
- `review_websocket_handler` — Socket.io handler review
- `review_celery_task` — Celery task review
- `review_api_design` — API design conventions review
- `review_performance` — Performance pattern review
- `review_accessibility` — WCAG 2.1 AA accessibility audit
- `review_file_upload` — File upload security review
- `suggest_tests` — Test strategy and test generation

### ScaffolderAgent

**Project Scaffolding (6 tools):**
- `scaffold_express_api` — Node/Express API scaffolding
- `scaffold_react_app` — React SPA scaffolding
- `scaffold_expo_app` — React Native/Expo app scaffolding
- `scaffold_saas_platform` — Full SaaS platform scaffolding
- `scaffold_fastapi_service` — FastAPI service scaffolding
- `generate_env_template` — .env.example template generation

### UIGenerationAgent ⭐ UPGRADED

**Claude-Powered UI Design & Component Building**

A world-class product-design persona (the taste behind Linear/Stripe/Vercel-caliber apps), not just a component generator — it establishes a real design system before it writes components, so output is cohesive rather than one-off.

**Tools:**
- `generate_design_system` — Establish a full design system/theme: color palette with rationale (primary + accent hue, neutral ramp, light/dark semantic tokens), type scale, spacing scale, radius scale, elevation/shadow scale, motion tokens
- `generate_component` — Generate React/TypeScript components from natural language, built on top of the design system's tokens
- `validate_accessibility` — WCAG 2.1 AA accessibility validation
- `apply_design_token` — Apply design tokens for consistent styling

**Key Features:**
- 🎨 Design-system-first: color theory, type scales, elevation, motion tokens — not ad-hoc styling
- ✨ Natural language to React components
- 💅 Tailwind CSS styling with restrained, premium use of gradients/glassmorphism/glow accents
- ♿ Accessibility-first (WCAG 2.1 AA), including contrast verification in both light and dark
- 🌓 Dark mode as a first-class palette, not an inverted afterthought
- 📱 Mobile-first responsive design
- 💬 Multi-turn conversation support
- 👁️ Wireframe/screenshot analysis
- 🧩 Component composition
- 🔄 Iterative refinement

**Usage Patterns:**
```python
# Establish the design system first
theme = agent.run("Design a theme for a career-advancement platform — trustworthy but energetic")

# Simple generation
result = agent.run("Create a button component")

# Multi-turn refinement
result = agent.run("Add hover effects", conversation_id="btn-v1")

# Wireframe analysis
response = agent.process_wireframe("From this image...", base64_data)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BaseAgent (Multi-Provider)              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐          ┌──────────────┐                │
│  │   OpenAI     │          │  Anthropic   │                │
│  │   Provider   │          │ (Claude)     │                │
│  └──────┬───────┘          └──────┬───────┘                │
│         │                         │                         │
│         └─────────┬───────────────┘                         │
│                   ▼                                         │
│         ┌─────────────────┐                                 │
│         │ Message Format  │                                 │
│         │   Handler       │                                 │
│         └────────┬────────┘                                 │
│                  │                                          │
│                  ▼                                          │
│         ┌─────────────────┐                                 │
│         │  Tool Engine    │                                 │
│         │  - OpenAI-      │                                 │
│         │    style        │                                 │
│         │  - Anthropic-   │                                 │
│         │    style        │                                 │
│         └────────┬────────┘                                 │
│                  │                                          │
│         ┌────────▼────────┐      ┌──────────────────┐       │
│         │    Agents       │─────►│   UI Agent (Anthropic)│  │
│         │  ┌──────────┐   │      └──────────────────┘       │
│         │  │Security  │   │                                  │
│         │  │Stripe    │   │      ┌──────────────────┐       │
│         │  │Railway   │   │─────►│   Other Agents   │       │
│         │  │Code      │   │      │  (Both Providers)│       │
│         │  │Scaffold  │   │      └──────────────────┘       │
│         │  └──────────┘   │                                  │
│         └─────────────────┘                                 │
└─────────────────────────────────────────────────────────────┘
```

**BaseAgent Features:**
- **Multi-provider support**: OpenAI and Anthropic out of the box
- **Unified API**: Same interface for both providers
- **Conversation management**: Multi-turn with conversation IDs
- **Tool execution**: Automatic tool calling and result handling
- **Error handling**: Graceful fallbacks and clear error messages

**UI Generation Agent Workflow:**
```
User Input (Natural Language)
           │
           ▼
┌──────────────────────┐
│  Claude Analysis     │
│  - Design intent     │
│  - Accessibility     │
│  - Responsiveness    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Tool Selection      │
│  - generate_component│
│  - validate_access   │
│  - apply_tokens      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Component Output    │
│  - React + TS        │
│  - Tailwind CSS      │
│  - Accessibility     │
│  - Usage examples    │
└──────────────────────┘
```

## Environment Variables

```fish
# OpenAI (optional if API key passed directly)
set -gx OPENAI_API_KEY "sk-..."

# Anthropic (optional if API key passed directly)
set -gx ANTHROPIC_API_KEY "sk-ant-..."

# Optional: Custom base URLs for proxy or self-hosted
set -gx OPENAI_BASE_URL "https://api.openai.com/v1"
set -gx ANTHROPIC_BASE_URL "https://api.anthropic.com"
```

## Running Examples

```fish
# Set API keys
set -gx OPENAI_API_KEY "sk-..."
set -gx ANTHROPIC_API_KEY "sk-ant-..."

# Run main examples (tool-level — no API key required for most)
python example.py

# Run comprehensive UI Generation Agent examples
python example_ui_generation.py
```

## Requirements

- Python 3.11+
- `openai>=1.0.0` — For OpenAI provider
- `anthropic>=0.40.0` — For Anthropic provider
- `class-variance-authority>=0.7.0` — Optional, for UI agent styling

## License

MIT

---

Built by [Rushing Technologies](https://rushingtechnologies.com) — solo operator, full stack + security + AI.

**Version 2.9.0** — Every agent mirrored as a Claude Code subagent, an `agents-scan` skill, and opt-in pre-commit/CI gating via `scan --fail-on`.
