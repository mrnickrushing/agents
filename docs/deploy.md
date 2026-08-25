# Deploying the hosted service, publishing releases

Everything in this repo runs locally with no infrastructure (`agents scan`).
Two things need infrastructure and this page is the runbook for both:

1. **The hosted service** — `agents serve`: the dashboard, the GitHub
   webhook receiver, and `/health`, on one Railway service behind a
   Cloudflare-proxied subdomain.
2. **Releases** — a `v*` tag publishes to PyPI (trusted publishing), GHCR
   (two images), and a GitHub Release.

## 1. Hosted service

### What runs

| Piece | Where |
|---|---|
| Image | `Dockerfile.server` (`agents serve` under gunicorn, non-root uid 10001) |
| Railway config | `railway.toml` — `dockerfilePath = "Dockerfile.server"`, healthcheck `/health` |
| State | `/data/rushingtech-agents/evolution.db` on a Railway volume (`XDG_STATE_HOME=/data`) |
| Public URL | `https://agents.rushingtechnologies.com` → Cloudflare CNAME (proxied) → Railway custom domain |

Routes: `/` dashboard · `/api/summary` · `/api/findings` · `/api/events` (SSE) ·
`/health` · `/ready` · `POST /webhook`.

### Railway service variables

| Variable | Purpose |
|---|---|
| `GITHUB_WEBHOOK_SECRET` | Shared secret on the GitHub webhook. Unset → `POST /webhook` answers 503 and everything else still serves. |
| `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_OAUTH_CLIENT_SECRET` | **Sign in with GitHub** for the *Run agents* panel. Either a classic OAuth App (Settings → Developer settings → OAuth Apps) or a **GitHub App** works; callback URL `https://agents.rushingtechnologies.com/auth/callback`. A GitHub App (client id starts with `Iv`) issues 8-hour user tokens with refresh tokens — the service renews them automatically — and only sees repositories it is **installed on**: give it *Contents: Read-only* and install it on your account, or the repository dropdown stays empty. The signed-in person's token lists their repositories and clones private ones — no `GITHUB_TOKEN` needed for that. |
| `PUBLIC_URL` | The one public origin (`https://agents.rushingtechnologies.com`). The OAuth callback is built from it, and any other hostname the service answers on (the generated `*.up.railway.app` domains) is redirected to it — otherwise a visit via a Railway domain produces a callback GitHub rejects ("redirect_uri is not associated with this application"). |
| `DASHBOARD_ALLOWED_LOGINS` | Comma-separated GitHub logins allowed to sign in (e.g. `mrnickrushing`). Anyone else gets a 403 after GitHub redirects back. Empty → nobody can sign in. |
| `SESSION_SECRET` | Signs the short-lived OAuth state cookie. Sessions themselves live in `/data/rushingtech-agents/sessions.db` (server side, 30 days) so a redeploy does not sign you out. |
| `DASHBOARD_TOKEN` | Optional fallback: `Authorization: Bearer …` for scripts/curl, and a *Use an access token instead* form on the sign-in page. With sign-in configured you can leave it unset. |
| `DASHBOARD_PUBLIC` | `1` keeps findings readable without signing in (only run/scan stay gated). Default off: once any sign-in method is configured, every page and API route redirects to `/login` / answers 401 until you sign in. `/health`, `/ready`, `/webhook`, and the home-screen assets stay public. |
| `GITHUB_TOKEN` | Lets the receiver fetch PR diffs and post the summary comment, and lets web-triggered scans clone private repositories. Without it the webhook scans the PR *body* only and posts nothing. Fine-grained PAT: Pull requests **read**, Issues **write** on the repos you point webhooks at. |
| `RAILWAY_RUN_UID=0` | Railway mounts volumes as root; the image runs as a non-root user. Railway's documented fix. |
| `XDG_STATE_HOME` | Already `/data` in the image; only override if the volume is mounted elsewhere. |
| `PORT=8000` | **Set it explicitly.** Railway otherwise injects its own value (8080 on first deploy) while the service domains target port 8000 — the result is a healthy container behind a 502. |
| `RAILWAY_DOCKERFILE_PATH=Dockerfile.server` | Belt and braces with the service's *Dockerfile path* setting. `railway.toml`'s `dockerfilePath` alone was **not** honored on the first build from the API — it built the CLI `Dockerfile` and the container exited after printing `--help`. |

Current production service: Railway project `agents` → service `agents-server`
(`agents-server-production-5f19.up.railway.app`, custom domain
`agents.rushingtechnologies.com`, volume `agents-server-data` at `/data`).

### Recreating it from scratch

```bash
railway login
railway init --name agents                       # or: railway link
railway volume add --mount-path /data
railway variables set RAILWAY_RUN_UID=0 PORT=8000 RAILWAY_DOCKERFILE_PATH=Dockerfile.server \
  GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"
railway up                                       # or connect the GitHub repo in the dashboard
railway domain agents.rushingtechnologies.com    # prints the CNAME target
```

Then in Cloudflare (zone `rushingtechnologies.com`) add **two** records —
Railway returns 404 "Application not found" on the custom domain until both
verify:

| Type | Name | Value | Proxy |
|---|---|---|---|
| CNAME | `agents` | `jh8ifzti.up.railway.app` (per-domain — read it from `railway domain status`, it is **not** the generic `cname.railway.app`) | proxied (orange) |
| TXT | `_railway-verify.agents` | `railway-verify=<token>` from `railway domain status` | DNS only |

```bash
railway domain status agents.rushingtechnologies.com --project <project-id> -s agents-server -e production --json
# .domain.dnsRecords[].requiredValue → CNAME target; .domain.verification.{dnsHost,token} → TXT
```

The MCP `generate-domain` call and the Railway dashboard agent only surface
the CNAME; the TXT record is the missing piece when the CNAME resolves but the
domain still 404s. Railway issues the certificate once
the record resolves; Cloudflare SSL mode must be *Full* (it is for the other
`*.rushingtechnologies.com` services).

### GitHub webhook

Per repository (or once at the org level):

- Payload URL: `https://agents.rushingtechnologies.com/webhook`
- Content type: `application/json`
- Secret: the same value as `GITHUB_WEBHOOK_SECRET`
- Events: **Pull requests** only

```bash
gh api repos/OWNER/REPO/hooks -f name=web -F active=true -f 'events[]=pull_request' \
  -f config[url]=https://agents.rushingtechnologies.com/webhook \
  -f config[content_type]=json -f config[secret]="$GITHUB_WEBHOOK_SECRET"
```

The receiver handles `opened`, `synchronize`, and `labeled` (labels
`agents-scan` / `security-review` opt a PR in). Each scan is recorded into the
evolution store, so it appears on the dashboard and in the SSE feed, and the
same `agents feedback <agf_id> dismiss` workflow applies.

### Verifying a deploy

```bash
curl -s https://agents.rushingtechnologies.com/health   # {"status":"ok","version":"..."}
curl -s https://agents.rushingtechnologies.com/ready    # {"status":"ready","database":"/data/..."}
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://agents.rushingtechnologies.com/webhook  # 401 (secret set) / 503 (not set)
```

### Running it anywhere else

```bash
pip install 'rushingtech-agents[web]' && agents serve
# or
docker compose up dashboard          # http://127.0.0.1:8000, state in the agents-state volume
```

## 2. Releases

Publishing is tag-driven and needs no long-lived secrets in the repo.

### One-time setup

1. **PyPI trusted publisher** (only a PyPI account owner can do this):
   pypi.org → *Publishing* → add a *pending* publisher for project
   `rushingtech-agents`, owner `mrnickrushing`, repository `agents`,
   workflow `publish-pypi.yml`, environment `pypi`. The first successful
   publish claims the name.
2. **GitHub environment `pypi`** must exist (`publish-pypi.yml` deploys to
   it); optionally add yourself as a required reviewer so a tag can't publish
   without a click.
3. **Actions → Workflow permissions**: "Allow GitHub Actions to create and
   approve pull requests" so `bump-version.yml` can open its PR.

### Cutting a release

```bash
gh workflow run bump-version.yml -f version=2.16.0   # opens a PR; merge it
git checkout main && git pull
git tag v2.16.0 && git push origin v2.16.0
```

The tag runs three workflows:

- `publish-pypi.yml` — tests, builds sdist + wheel, `twine check`, publishes
  via OIDC, then creates the GitHub Release with generated notes.
- `publish-container.yml` — `ghcr.io/mrnickrushing/agents` (CLI image) and
  `ghcr.io/mrnickrushing/agents-server` (hosted service), tagged
  `2.16.0`, `2.16`, `latest`.
- Railway redeploys from `main` on its own; a tag does not change that.

Verify: `pip index versions rushingtech-agents`, `docker pull
ghcr.io/mrnickrushing/agents-server:latest`, and the Releases page.
