# Personal MCP Server — Specification

**Status:** proposed · **Target:** `agents/mcp_server/` in this repo · **Phase 1 scope:** read-only

A single MCP server that makes every Rushing Technologies project queryable from
inside Claude, instead of from eight browser tabs. Phase 1 is read-only across
repos, deploys, and errors. Write actions land later, behind a credential gate,
once the read side has earned trust.

---

## 1. The one rule that decides what gets built

Railway, GitHub, Cloudflare, and Expo all already ship MCP servers, and they are
already connected. Re-wrapping them adds tools without adding answers.

> **Build a tool only if it answers a question no connected server can answer in
> one call.** In practice that means two things, and only two things:
>
> 1. **Joins.** "Which commit is live on the API right now, and did the errors
>    start after it shipped?" No single vendor knows both halves. This server
>    does, because it owns the mapping between them.
> 2. **Local knowledge.** The scan findings, verdicts, and feedback history in
>    `evolution.db`, and the source in the local checkouts. No vendor server can
>    see any of it.

Everything below follows from that rule. A tool that is a thin proxy for
`mcp__Railway__list-deployments` does not get written.

---

## 2. Architecture

```
Claude Code / Desktop
        │  stdio (JSON-RPC)
        ▼
┌───────────────────────────────────────────────┐
│  agents.mcp_server                            │
│                                               │
│  registry.py   projects.toml → canonical IDs  │
│  secrets.py    keychain → tokens (never disk) │
│  redact.py     outbound scrub, runs on all    │
│  audit.py      append-only JSONL of every call│
│                                               │
│  sources/  github  railway  sentry  expo      │
│            evolution (local sqlite)           │
│            code     (local checkouts)         │
└───────────────────────────────────────────────┘
```

**Transport: stdio, local process.** No listener, no OAuth, no callback URL, no
deployed surface to secure. Credentials stay on the machine that already holds
them. Remote access is Phase 3 and only if it is actually wanted from mobile.

**Language: Python 3.11, official `mcp` SDK, in this repo.** The strongest
single differentiator — `scan_findings` — is a direct in-process call to
`agents.evolution.EvolutionStore`. In a separate repo that becomes a subprocess
boundary or a duplicated schema. Add as an optional extra so the core package
stays dependency-light:

```python
extras_require={
    "dev": ["pytest", "black", "ruff"],
    "mcp": ["mcp>=1.2.0", "httpx>=0.27", "keyring>=25.0"],
}
```

> **Footgun:** name the package `agents/mcp_server/`, not `agents/mcp/`. The
> latter reads fine but makes `import mcp` inside it ambiguous to every human
> who later opens the file.

### Registration

`.mcp.json` at the repo root (project-scoped, so it travels with the checkout):

```json
{
  "mcpServers": {
    "rushingtech": {
      "command": "python",
      "args": ["-m", "agents.mcp_server"],
      "env": { "RUSHINGTECH_PROJECTS": "~/.config/rushingtech/projects.toml" }
    }
  }
}
```

---

## 3. The registry — the thing that makes the joins possible

One file is the primary key for everything. It holds **identifiers only, never
secrets**, so it is safe to sync between machines.

`~/.config/rushingtech/projects.toml` (path overridable via
`RUSHINGTECH_PROJECTS`; a `projects.example.toml` ships in the repo):

```toml
schema = 1

[defaults]
sentry_org   = "rushingtech"
expo_account = "rushingtech"

[projects.vitality]
display_name = "Vitality"
aliases      = ["vit", "vitality-app"]
stack        = ["expo", "fastapi", "postgres"]
local_path   = "~/Vitality"

github  = ["mrnickrushing/vitality", "mrnickrushing/vitality-api"]
railway = { project = "prj_xxx", services = ["api", "worker"] }
sentry  = { projects = ["vitality-api", "vitality-mobile"] }
expo    = { slug = "vitality" }
stripe  = { account = "acct_xxx", livemode = true }
domains = ["vitality.app"]
```

Every field is optional except `github` **or** `local_path`. A project with only
a `local_path` still works for `search_code` and `scan_findings` — which means
new projects become queryable the moment they are added, before any
infrastructure exists for them. That is the compounding part.

**Resolution:** every tool takes a fuzzy `project` string and resolves it
through key → alias → display name → repo name → substring, in that order. An
unresolvable name returns the list of valid names rather than an error string,
so Claude self-corrects in one turn instead of guessing twice.

---

## 4. Tool list — Phase 1 (read-only, 8 tools)

Eight is deliberate. Every tool costs context in every conversation, and a
30-tool server makes the model worse at choosing among them. Hard cap: **12**.

| # | Tool | Answers |
|---|------|---------|
| 1 | `list_projects` | What exists, and what is wired to each project |
| 2 | `get_project_status` | Everything about one project, in one call |
| 3 | `whats_broken` | Across all projects, what needs me today |
| 4 | `recent_deploys` | What shipped, where, and did it land |
| 5 | `recent_errors` | What is failing in production, grouped |
| 6 | `deploy_diff` | Which commits are in this deploy but not the last |
| 7 | `search_code` | Where do I do X, across every repo at once |
| 8 | `scan_findings` | What did the scanner find that is still open |

### 1. `list_projects`

```python
list_projects(detail: bool = False) -> str
```
No arguments in the common case. Returns names, stacks, and which sources are
wired. This is the tool Claude calls first in a fresh conversation to learn the
vocabulary of every other tool.

### 2. `get_project_status` — the one that replaces the tabs

```python
get_project_status(
    project: str,
    include: list[str] = ["repo", "deploy", "errors", "scan"],  # + "billing"
) -> str
```

Fans out concurrently, degrades per-source, and renders ~200 tokens:

```
Vitality — attention (as of 14:22 UTC)

repo    mrnickrushing/vitality      main 3f2a91c "fix push token refresh" (4h)
        CI passing · 2 open PRs (#88 ready 6d, #91 draft 1d)
        mrnickrushing/vitality-api  main a17c003 "bump alembic" (2d)
        CI passing · no open PRs

deploy  railway/api     SUCCESS  2d ago  a17c003
        railway/worker  SUCCESS  2d ago  a17c003
        eas/vitality    ios 1.4.2 (6d) · android 1.4.2 (6d)

errors  vitality-api     14 events / 3 issues (24h)
          9x  httpx.ReadTimeout   api/services/ai.py:88   NEW 3h ago
        vitality-mobile   2 events / 1 issue (24h)

scan    5 open findings (1 HIGH, 4 MEDIUM) · last scan 9d ago

degraded: none
```

**Rules that make this tool good rather than merely present:**
- A source that times out (3s) prints under `degraded:` — it never silently
  omits, because a missing section that reads as "fine" is the failure mode that
  destroys trust in the whole server.
- The one-word verdict on line 1 (`healthy` / `attention` / `broken`) is derived,
  not vibes: `broken` = failed deploy or red CI on default branch; `attention` =
  new error group, or an open non-draft PR older than 5 days.
- Never dumps raw API JSON. Returns IDs only where a follow-up tool needs them.

### 3. `whats_broken`

```python
whats_broken(since_hours: int = 24) -> str
```
Zero-argument sweep over every registered project. **Returns only what is
actionable, and returns nothing when nothing is wrong** — a report listing eight
healthy projects trains you to stop reading it. This is the morning tool, and
the one worth putting on a schedule later.

### 4. `recent_deploys`

```python
recent_deploys(project: str | None = None, limit: int = 10,
               status: str = "all") -> str  # all|failed|success
```
One timeline across Railway, EAS, and Cloudflare, newest first, each row
carrying its commit SHA. Cross-platform ordering is the value; a per-platform
list is already a vendor tool.

### 5. `recent_errors`

```python
recent_errors(project: str | None = None, since_hours: int = 24,
              limit: int = 10, min_events: int = 1) -> str
```
Sentry issues **grouped**, with count, first-seen, last-seen, culprit, and a
`NEW` marker for anything first seen inside the window. Sorted by "new and
frequent" rather than raw count, so a long-standing noisy warning cannot bury a
regression that started an hour ago.

### 6. `deploy_diff`

```python
deploy_diff(project: str, deployment: str = "latest",
            against: str = "previous") -> str
```
The join that pays for the whole server: commits present in one deploy and not
the other, plus files touched. Turns "the API started timing out yesterday" into
"these four commits shipped 40 minutes before the first timeout."

### 7. `search_code`

```python
search_code(query: str, projects: list[str] | None = None,
            path_glob: str | None = None, limit: int = 20) -> str
```
Ripgrep across every `local_path` in the registry, honoring the same exclusions
`agents/cli.py` already defines (`EXCLUDED_DIRS`). For a solo operator with the
same Stripe webhook verification written five times, "show me every place I
verify a Svix signature" is a genuinely new capability. Falls back to the GitHub
code search API for projects with no local checkout.

### 8. `scan_findings`

```python
scan_findings(project: str, severity: str | None = None,
              status: str = "open") -> str  # open|confirmed|dismissed|all
```
Straight through to `EvolutionStore.recent_runs()` / `evaluate()`. No new
credential, no network, and no other MCP server on earth can answer it. Include
`finding_id` in the output so the Phase 1.5 write tool can act on it.

---

## 5. Tool list — later phases

**Phase 1.5 — local writes (low risk, no remote blast radius):**

| Tool | Notes |
|------|-------|
| `record_finding_verdict(finding_id, verdict, note)` | Wraps the existing `agents.cli feedback`. Writes only to local sqlite. Closes the evolution loop from inside a conversation, which is where the verdict is actually formed. |

**Phase 2 — remote writes (gated, see §6):**

| Tool | Risk | Order |
|------|------|-------|
| `write_create_issue` | Low — reversible, no production effect | 1st |
| `write_redeploy` | Medium — reruns a known-good build | 2nd |
| `write_rollback` | Medium — but it is the tool you want at 2am | 3rd |
| `write_set_env_var` | **High** — can take production down, and values are secrets | last, if ever |

Add them one at a time, each after a week of the audit log showing the read side
behaving. Adding all four at once means a bad turn has four ways to hurt.

---

## 6. Auth

### The principle: read-only is a property of the credential, not of the code

Code-level read-only is one refactor away from being wrong. A token that
physically cannot write is read-only forever. Phase 1 mints credentials that
cannot perform the actions Phase 1 does not offer.

| Source | Credential | Read-only scopes |
|--------|-----------|------------------|
| GitHub | Fine-grained PAT, **repo-selected** | Contents: Read · Metadata: Read · Pull requests: Read · Actions: Read · Issues: Read |
| Sentry | Org auth token | `org:read`, `project:read`, `event:read` |
| Stripe | Restricted key | Read on Charges / Subscriptions / Invoices only |
| Expo | Robot access token | Read — *verify the tier at implementation; confirm before assuming* |
| Railway | Project token, per project where possible | **No read-only tier exists.** See below. |

> **Railway is the honest exception.** Railway tokens are not scope-granular —
> an account or team token can do anything the account can do. Read-only cannot
> be enforced by the credential there. Mitigations, in order: prefer a
> **project-scoped** token so blast radius is one project; enforce read-only in
> the client (no write method is even implemented in Phase 1); and rely on the
> audit log to prove it. Do not describe the Railway path as read-only-enforced,
> because it is not.

### Storage

OS keychain, via `keyring`, under service `rushingtech-mcp`:

```
rushingtech-mcp/github    rushingtech-mcp/sentry
rushingtech-mcp/railway   rushingtech-mcp/expo    rushingtech-mcp/stripe
```

Env vars are a fallback for CI and containers only. **No `.env` in this repo** —
it is a public repo with a scanner in it, and a leaked token in a security tool's
own repo is the worst possible headline.

### Outbound secret scrubbing

`redact.py` runs on every tool response before it leaves the process, matching
known token shapes (`ghp_`, `github_pat_`, `sk_live_`, `rk_live_`, `sntrys_`,
`AKIA`, JWT triplets, and any value that equals a loaded credential) and
replacing them with `«redacted»`. A test plants each shape in a fixture response
and asserts none survives. Even in Phase 2, env-var tools return **names only,
never values**.

### Audit log

Append-only JSONL at `~/.local/state/rushingtech-mcp/audit.jsonl`:

```json
{"ts":"2026-08-22T14:22:03Z","tool":"get_project_status","args":{"project":"vitality"},
 "sources":["github","railway","sentry"],"ms":842,"ok":true,"degraded":[]}
```

This is not bureaucracy — it is the mechanism by which "add write actions once
you trust it" becomes a decision based on evidence instead of a feeling. Two
weeks of reading it tells you exactly which tools fire, how often, and whether
anything surprising happened.

### Write gate (Phase 2)

Three independent locks, all required:

1. `RUSHINGTECH_MCP_WRITE=1` in the server env.
2. A **separate** write-capable credential (`rushingtech-mcp/github-write`). The
   read token stays read-only forever; write capability is a distinct secret.
3. `confirm: true` in the tool arguments — the model must state intent
   explicitly, on top of Claude Code's own permission prompt.

Name every write tool `write_*` so they are trivially greppable in the audit log
and easy to enumerate in a deny rule. For blanket denial, the server-wide form
`mcp__rushingtech` is the rule that reliably matches.

### Phase 3 — remote (only if wanted from mobile)

Cloudflare Worker, Streamable HTTP, OAuth 2.1 + PKCE, GitHub as the identity
provider with a one-name allowlist. Secrets in Worker secrets, never KV.
Realistically a full day, and it buys nothing when the machine is in front of
you. Defer until there is an actual "I want this from my phone" moment.

---

## 7. Non-functional requirements

**Concurrency and degradation.** `get_project_status` and `whats_broken` fan out
with `asyncio.gather(..., return_exceptions=True)` and a 3s per-source timeout.
One dead API returns a partial answer plus a `degraded:` line. Never hang; never
silently omit.

**Cache.** 60s TTL, in-memory, keyed by `(source, endpoint, args)`. A single
Claude turn often calls `get_project_status` then `recent_errors` for the same
project — that should be one round of fetches, not two.

**Response budget.** Default ≤ 800 tokens per tool response; `detail: true`
opts into more. The reason to have this server is fewer tokens spent on context
gathering, not more.

**Staleness.** Every response carries an "as of" timestamp. A cached answer that
looks live is worse than a slow one.

---

## 8. Tests

The existing suite is precision-obsessed — 18 test files, most of them written
after a heuristic fired on correct code. The MCP analog of a false positive is a
**wrong or stale join**, and it deserves the same treatment.

| Test | Asserts |
|------|---------|
| `test_registry.py` | Resolution order, alias collisions, unknown name lists valid names, malformed TOML fails loudly at startup |
| `test_redaction.py` | Each token shape planted in a fixture response is scrubbed; a loaded credential never appears in output |
| `test_degradation.py` | A source raising / timing out yields a partial answer with `degraded`, and **never** a `healthy` verdict |
| `test_stale_join.py` | A registry pointing at a deleted Railway service reports "not found", not "no deploys" — silence must not read as success |
| `test_tool_schemas.py` | Every registered tool has a valid JSON Schema and a description that names its arguments |
| `test_response_budget.py` | Fixture-driven responses stay under budget |

All against recorded fixtures. **No live API calls in CI** — the existing
workflow runs `pytest -q` on every PR with no secrets available, and it stays
that way.

---

## 9. First session — 2.5 hours, seven steps

Goal: `list_projects`, `get_project_status`, and `scan_findings` working in
Claude Code against two real projects. Nothing else. Each step ends in something
verifiable, so a bad step is caught in ten minutes rather than at the end.

**1 · Handshake (20 min).** `pip install "mcp[cli]"`. Create
`agents/mcp_server/__main__.py` with exactly one tool: `ping`. Add `.mcp.json`.
✅ *Done when:* `/mcp` in Claude Code shows `rushingtech` connected and `ping`
returns. Do this before any real logic — most MCP pain is transport and
registration, and it is worth isolating.

**2 · Registry (20 min).** `projects.toml` schema, loader, validation, fuzzy
resolver. **Two projects only** — Vitality and shield-ai.
✅ *Done when:* `list_projects` returns both, and a test proves an unknown name
returns the valid names.

**3 · Credentials (20 min).** `secrets.py` (keychain, env fallback). Mint the
GitHub fine-grained PAT scoped to just those repos, read-only. Write
`python -m agents.mcp_server.doctor`.
✅ *Done when:* `doctor` prints a per-source ✅/❌ with what is missing, and
prints no token under any condition.

**4 · First real tool (35 min).** `get_project_status`, GitHub only: head SHA,
message, age, open PR count, latest CI conclusion. Compact markdown.
✅ *Done when:* asking Claude "what's the state of Vitality?" produces a correct
answer with no other tool calls.

**5 · Redaction + audit (20 min).** `redact.py` and `audit.py` wired into the
dispatcher so every future tool inherits both. Add `test_redaction.py`.
✅ *Done when:* the test is green and `audit.jsonl` contains step 4's calls.

*(Doing this at step 5, not step 12, is the whole difference between a server
you trust with writes later and one you never quite do.)*

**6 · Second source (30 min).** Railway: last deploy status, time, and commit on
the status card. 3s timeout, graceful degradation.
✅ *Done when:* removing the Railway token still returns the GitHub half plus
`degraded: railway`.

**7 · The local edge (25 min).** `scan_findings` over the existing
`evolution.db` via `EvolutionStore`. No new credentials, no network.
✅ *Done when:* Claude answers "what's still open from the last Vitality scan?"

**Then stop.** Do not add tools 3–7 from §4 in this session. Two working tools
and a trustworthy foundation beat eight half-wired ones, and the next session
starts from something already useful.

### Subsequent sessions

- **Session 2:** Sentry → `recent_errors`, then `whats_broken`. Add concurrency
  and the TTL cache once three sources exist and the fan-out is real.
- **Session 3:** `search_code` and `deploy_diff`. Add the remaining projects to
  the registry — this is the session where the compounding shows up, because
  each new project costs one TOML block.
- **Session 4:** Phase 1.5 `record_finding_verdict`, then the write gate and
  `write_create_issue`. Read the audit log before deciding.
- **Later, optional:** a scheduled `whats_broken` each weekday morning; Phase 3
  remote access only if it is genuinely missed from mobile.

---

## 10. How this fails, and the counter

| Failure | Counter |
|---------|---------|
| **Registry rot** — IDs change, services get deleted, the map quietly lies | `doctor` validates every ID against its API; stale joins report "not found", never a healthy-looking silence |
| **Tool sprawl** — 30 tools, model picks wrong, every conversation pays | Hard cap of 12; a new tool must answer something no existing tool answers in one call |
| **Context bloat** — the server costs more tokens than the tabs did | Response budget with fixture-enforced tests; `detail` is opt-in |
| **Vendor duplication** — slowly re-implementing the Railway MCP server | §1 is the standing rule: joins and local knowledge only |
| **Stalled at read-only** — never trusted enough to add writes | The audit log makes the trust decision empirical, and Phase 1.5 starts with local-sqlite writes that cannot hurt production |
| **Credential sprawl** — five tokens, unclear scopes, one leaks | Keychain only, per-source, least-privilege, outbound scrubbing, and never a `.env` in this repo |

---

## 11. Open questions

1. **Expo robot tokens** — confirm a read-only tier exists before assuming it in
   the credential table. If not, Expo joins Railway as a code-enforced exception.
2. **Stripe in Phase 1** — billing status is genuinely useful on the status card
   for the revenue-generating apps, but it is also the highest-sensitivity source.
   Suggest deferring to Session 3 and minting the restricted key then.
3. **Scheduled `whats_broken`** — worth wiring to a morning trigger, but only
   after it has run manually for a week and proven it stays quiet when things
   are fine.
