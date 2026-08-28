"""config_audit — the surfaces the code scanners never looked at.

Every positive case here is modelled on a real file from the fleet baseline;
every negative case is the pattern the fleet already gets right. A rule that
fires on the correct case is worse than no rule (session 12 lesson), so
each check has both.
"""

import textwrap

import pytest

from agents.config_audit import ConfigAuditAgent


@pytest.fixture
def agent():
    return ConfigAuditAgent()


def _issues(result):
    return [f["issue"] for f in result["findings"]]


def _severities(result):
    return {f["severity"] for f in result["findings"]}


# --- Dockerfile ---------------------------------------------------------------------


def test_dockerfile_without_user_in_final_stage_runs_as_root(agent):
    df = 'FROM python:3.13-slim\nCOPY . .\nRUN pip install --no-cache-dir -r requirements.txt\nCMD ["python", "app.py"]\n'
    issues = _issues(agent._audit_dockerfile(df))
    assert any("runs as root" in i for i in issues)


def test_dockerfile_builder_stage_as_root_is_fine_if_runner_drops_privileges(agent):
    df = textwrap.dedent("""
        FROM node:26-alpine AS build
        RUN npm ci && npm run build
        FROM python:3.14-slim
        RUN useradd -m app
        USER app
        CMD ["python", "app.py"]
    """)
    assert not any("root" in i for i in _issues(agent._audit_dockerfile(df)))


def test_dockerfile_user_root_explicitly_still_counts_as_root(agent):
    df = 'FROM node:20-alpine\nUSER root\nCMD ["node"]\n'
    assert any("runs as root" in i for i in _issues(agent._audit_dockerfile(df)))


@pytest.mark.parametrize(
    "base,flagged",
    [
        ("node:20.19.4-alpine", False),
        ("python:3.12-slim", False),
        ("node", True),
        ("node:latest", True),
        ("ghcr.io/org/img", True),
        ("ghcr.io/org/img:1.2", False),
        ("node@sha256:" + "a" * 64, False),
        ("scratch", False),
    ],
)
def test_dockerfile_unpinned_base_detection(agent, base, flagged):
    df = f"FROM {base}\nUSER app\n"
    hits = [i for i in _issues(agent._audit_dockerfile(df)) if "unpinned" in i]
    assert bool(hits) == flagged


def test_dockerfile_secret_in_env_is_critical_but_placeholders_are_not(agent):
    df = "FROM node:20-alpine\nENV API_KEY=sk_live_abcdefghijklmnop\nUSER app\n"
    r = agent._audit_dockerfile(df)
    assert "CRITICAL" in _severities(r)
    assert any("baked into the image" in i for i in _issues(r))

    ok = "FROM node:20-alpine\nENV API_KEY=your-key-here\nARG DATABASE_URL=${DATABASE_URL}\nUSER app\n"
    assert "CRITICAL" not in _severities(agent._audit_dockerfile(ok))


def test_dockerfile_curl_pipe_sh(agent):
    df = "FROM debian:12\nRUN curl -fsSL https://get.example.com | sh\nUSER app\n"
    assert any(
        "straight into a shell" in i for i in _issues(agent._audit_dockerfile(df))
    )


# --- docker-compose ------------------------------------------------------------------


def test_compose_dev_password_and_published_db_port_are_low(agent):
    yml = textwrap.dedent("""
        services:
          db:
            image: postgres:16
            environment:
              POSTGRES_PASSWORD: dev
            ports:
              - "5432:5432"
    """)
    r = agent._audit_compose(yml)
    assert _severities(r) == {"LOW"}
    assert len(r["findings"]) == 2


def test_compose_loopback_bound_port_is_not_flagged(agent):
    yml = 'services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"\n'
    assert agent._audit_compose(yml)["findings"] == []


def test_compose_privileged_is_high(agent):
    yml = "services:\n  agent:\n    privileged: true\n"
    r = agent._audit_compose(yml)
    assert "HIGH" in _severities(r)


def test_compose_interpolated_password_is_not_a_literal(agent):
    yml = "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-dev}\n"
    assert agent._audit_compose(yml)["findings"] == []


# --- GitHub Actions ---------------------------------------------------------------------

WF = ".github/workflows/ci.yml"


def test_workflow_outside_workflows_dir_is_ignored(agent):
    assert (
        agent._audit_workflow("on: push\njobs: {}\n", path="docker-compose.yml")[
            "findings"
        ]
        == []
    )
    assert (
        agent._audit_workflow("on: push\njobs: {}\n", path="codemagic.yaml")["findings"]
        == []
    )


def test_workflow_unpinned_actions_graded_by_party(agent):
    wf = textwrap.dedent("""
        permissions: { contents: read }
        jobs:
          t:
            steps:
              - uses: actions/checkout@v4
              - uses: aquasecurity/trivy-action@v0.36.0
              - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
              - uses: ./.github/actions/local
    """)
    r = agent._audit_workflow(wf, path=WF)
    by = {f["issue"]: f["severity"] for f in r["findings"]}
    assert (
        by["`actions/checkout@v4` is pinned to a mutable tag, not a commit SHA"]
        == "LOW"
    )
    assert (
        by[
            "`aquasecurity/trivy-action@v0.36.0` is pinned to a mutable tag, not a commit SHA"
        ]
        == "MEDIUM"
    )
    assert len(r["findings"]) == 2  # the SHA-pinned and local ones are fine


def test_workflow_missing_permissions_block(agent):
    wf = "on: push\njobs:\n  t:\n    steps:\n      - run: echo hi\n"
    assert any(
        "No `permissions:` block" in i
        for i in _issues(agent._audit_workflow(wf, path=WF))
    )
    wf_ok = "on: push\npermissions:\n  contents: read\njobs: {}\n"
    assert not any(
        "permissions" in i for i in _issues(agent._audit_workflow(wf_ok, path=WF))
    )


def test_workflow_pull_request_target_with_checkout_is_critical(agent):
    wf = "on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
    r = agent._audit_workflow(wf, path=WF)
    assert "CRITICAL" in _severities(r)


def test_workflow_expression_injection(agent):
    wf = textwrap.dedent("""
        permissions: { contents: read }
        on: pull_request
        jobs:
          t:
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
    """)
    assert any(
        "crafted PR title" in i for i in _issues(agent._audit_workflow(wf, path=WF))
    )

    safe = textwrap.dedent("""
        permissions: { contents: read }
        jobs:
          t:
            steps:
              - env:
                  TITLE: ${{ github.event.pull_request.title }}
                run: echo "$TITLE"
    """)
    assert not any(
        "crafted" in i for i in _issues(agent._audit_workflow(safe, path=WF))
    )


# --- Android ------------------------------------------------------------------------------


def test_android_cleartext_and_backup(agent):
    manifest = (
        '<application android:usesCleartextTraffic="true" android:allowBackup="true">'
    )
    r = agent._audit_android_manifest(manifest, path="app/src/main/AndroidManifest.xml")
    assert any("plain HTTP" in i for i in _issues(r))
    assert any("adb backup" in i for i in _issues(r))


def test_android_debug_variant_cleartext_is_expected_not_flagged(agent):
    """Debug manifests allow cleartext so Metro can reach the dev server;
    they never ship. All three fleet hits were debug variants."""
    manifest = '<application android:usesCleartextTraffic="true">'
    for path in (
        "app/src/debug/AndroidManifest.xml",
        "app/src/debugOptimized/AndroidManifest.xml",
    ):
        assert not any(
            "plain HTTP" in i
            for i in _issues(agent._audit_android_manifest(manifest, path=path))
        )


def test_android_exported_service_without_permission(agent):
    manifest = textwrap.dedent("""
        <application>
          <activity android:name=".MainActivity" android:exported="true"/>
          <service android:name=".SyncService" android:exported="true"/>
          <receiver android:name=".Boot" android:exported="true" android:permission="android.permission.RECEIVE_BOOT_COMPLETED"/>
          <provider android:name=".Files" android:exported="false"/>
        </application>
    """)
    issues = _issues(agent._audit_android_manifest(manifest))
    assert any("Exported service `.SyncService`" in i for i in issues)
    assert not any(
        "MainActivity" in i for i in issues
    )  # activities are exported on purpose
    assert not any(".Boot" in i for i in issues)  # gated by a permission


def test_android_debuggable_is_critical(agent):
    r = agent._audit_android_manifest('<application android:debuggable="true">')
    assert "CRITICAL" in _severities(r)


# --- iOS --------------------------------------------------------------------------------------


def test_ios_arbitrary_loads_true_flagged_false_not(agent):
    bad = "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>"
    assert any(
        "Transport Security is disabled" in i
        for i in _issues(agent._audit_ios_plist(bad))
    )
    # The real shield-ai plist: ArbitraryLoads false, LocalNetworking true.
    ok = "<key>NSAllowsArbitraryLoads</key>\n<false/>\n<key>NSAllowsLocalNetworking</key>\n<true/>"
    assert agent._audit_ios_plist(ok)["findings"] == []


# --- wrangler -----------------------------------------------------------------------------------


def test_wrangler_secret_in_vars_is_critical(agent):
    toml = 'name = "w"\n[vars]\nAPI_TOKEN = "abcdefghijklmnopqrstuvwxyz1234"\nPUBLIC_URL = "https://x"\n\n[[kv_namespaces]]\nbinding = "KV"\n'
    r = agent._audit_wrangler(toml)
    assert _severities(r) == {"CRITICAL"}
    assert len(r["findings"]) == 1


def test_wrangler_real_fleet_file_is_clean(agent):
    toml = 'name = "wingman-admin"\nmain = "src/index.ts"\ncompatibility_date = "2025-01-01"\n\n[[d1_databases]]\nbinding = "DB"\n'
    assert agent._audit_wrangler(toml)["findings"] == []


# --- Railway --------------------------------------------------------------------------------------


def test_railway_healthcheck_path_with_no_route_is_high(agent, tmp_path):
    (tmp_path / "railway.toml").write_text('[deploy]\nhealthcheckPath = "/health"\n')
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(
        '@app.get("/api/v1/scans")\ndef scans(): ...\n'
    )
    r = agent._audit_railway_config(
        (tmp_path / "railway.toml").read_text(), path=str(tmp_path / "railway.toml")
    )
    assert "HIGH" in _severities(r)
    assert any("`/health`" in i for i in _issues(r))


def test_railway_healthcheck_path_that_a_route_serves_is_fine(agent, tmp_path):
    (tmp_path / "railway.json").write_text('{"deploy": {"healthcheckPath": "/health"}}')
    (tmp_path / "server.ts").write_text(
        "app.get('/health', (_, res) => res.json({ ok: true }));"
    )
    r = agent._audit_railway_config(
        (tmp_path / "railway.json").read_text(), path=str(tmp_path / "railway.json")
    )
    assert r["findings"] == []


def test_railway_root_healthcheck_is_not_checked(agent, tmp_path):
    (tmp_path / "railway.toml").write_text('healthcheckPath = "/"\n')
    r = agent._audit_railway_config(
        'healthcheckPath = "/"\n', path=str(tmp_path / "railway.toml")
    )
    assert r["findings"] == []


# --- .env.example -------------------------------------------------------------------------------------


def test_env_example_real_looking_secret_is_high(agent):
    r = agent._audit_env_example("JWT_SECRET=f8a3b9c2d4e5f6a7b8c9d0e1f2a3b4c5\n")
    assert "HIGH" in _severities(r)
    ok = agent._audit_env_example(
        "JWT_SECRET=your-secret-here\nDATABASE_URL=postgres://user:pass@localhost/db\n"
    )
    assert ok["findings"] == []


def test_env_example_fleet_placeholders_are_not_secrets(agent):
    """The first fleet run flagged seven of these; every one was a template
    value. Real placeholders from the fleet, verbatim shapes."""
    content = (
        "JWT_SECRET=change-me-in-production-min-32-chars\n"
        "SESSION_SECRET=changeme-use-openssl-rand-hex-32-in-production\n"
        "ADMIN_API_KEY=replace-with-a-long-random-string\n"
        "POSTGRES_PASSWORD=REPLACE_WITH_STRONG_PASSWORD\n"
        "SIGNING_KEY=generate-with-openssl-rand-base64\n"
    )
    assert agent._audit_env_example(content)["findings"] == []


def test_env_example_revenuecat_public_sdk_keys_are_not_secrets(agent):
    """`appl_...` / `goog_...` identify the app to the SDK and cannot
    authorize server calls; committing them is expected."""
    content = "EXPO_PUBLIC_REVENUECAT_API_KEY=appl_MnpFxWABCDEFGHIJKLMNOPQRSTU\n"
    assert agent._audit_env_example(content)["findings"] == []


def test_env_example_undocumented_usage_is_found_across_the_tree(agent, tmp_path):
    (tmp_path / ".env.example").write_text("DATABASE_URL=\nSENTRY_DSN=\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.ts").write_text(
        "const db = process.env.DATABASE_URL;\nconst key = process.env.STRIPE_SECRET_KEY;\nconst port = process.env.PORT;\n"
    )
    (tmp_path / "worker.py").write_text(
        'import os\nos.environ["REDIS_URL"]\nos.getenv("SENTRY_DSN")\n'
    )
    (tmp_path / "src" / "config.test.ts").write_text("process.env.ONLY_IN_TESTS")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("process.env.SHOULD_BE_IGNORED")

    r = agent._audit_env_example(
        (tmp_path / ".env.example").read_text(), path=str(tmp_path / ".env.example")
    )
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    assert f["undocumented"] == [
        "REDIS_URL",
        "STRIPE_SECRET_KEY",
    ]  # PORT ignored, node_modules skipped
    assert "config.ts" in f["fix"] or "worker.py" in f["fix"]


def test_env_example_fully_documented_is_clean(agent, tmp_path):
    (tmp_path / ".env.example").write_text("DATABASE_URL=\n")
    (tmp_path / "a.py").write_text('os.getenv("DATABASE_URL")')
    r = agent._audit_env_example("DATABASE_URL=\n", path=str(tmp_path / ".env.example"))
    assert r["findings"] == []


# --- registration -----------------------------------------------------------------------------------------


def test_config_audit_is_wired_into_the_scan_rules():
    from agents.cli import AGENTS, RULES

    assert "config_audit" in AGENTS
    globs = {r[0] for r in RULES if r[2] == "config_audit"}
    assert {
        "Dockerfile*",
        "AndroidManifest.xml",
        "Info.plist",
        "wrangler.toml",
        ".env.example",
        "railway.toml",
    } <= globs


def test_a_privilege_dropping_entrypoint_is_not_running_as_root(tmp_path):
    """A container that starts as root only to hand a mounted volume to its
    runtime user, then drops and execs the service, is not running as root.
    It cannot use USER — a volume is mounted over its directory after the
    build, so a build-time chown never reaches it (backgrounds, 2026-08-28)."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN useradd --uid 10001 app\n"
        "COPY . /app\n"
        'ENTRYPOINT ["python3", "/app/docker-entrypoint.py"]\n'
        'CMD ["python3", "-m", "app"]\n'
    )
    (tmp_path / "docker-entrypoint.py").write_text(
        "import os, pwd\n"
        "account = pwd.getpwnam('app')\n"
        "os.setgid(account.pw_gid)\n"
        "os.setuid(account.pw_uid)\n"
        "os.execvp('python3', ['python3'])\n"
    )
    result = ConfigAuditAgent()._audit_dockerfile(
        dockerfile.read_text(), str(dockerfile)
    )
    assert not any("runs as root" in f["issue"] for f in result["findings"])


def test_an_entrypoint_that_does_not_drop_privileges_is_still_reported(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "COPY . /app\n"
        'ENTRYPOINT ["/app/entrypoint.sh"]\n'
        'CMD ["python3", "-m", "app"]\n'
    )
    (tmp_path / "entrypoint.sh").write_text('#!/bin/sh\nexec "$@"\n')
    result = ConfigAuditAgent()._audit_dockerfile(
        dockerfile.read_text(), str(dockerfile)
    )
    assert any("runs as root" in f["issue"] for f in result["findings"])


def test_an_unreadable_entrypoint_does_not_vouch_for_the_container(tmp_path):
    """The script is not in the build context, so nothing proves it drops."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        'ENTRYPOINT ["/usr/local/bin/entry.sh"]\n'
        'CMD ["python3"]\n'
    )
    result = ConfigAuditAgent()._audit_dockerfile(
        dockerfile.read_text(), str(dockerfile)
    )
    assert any("runs as root" in f["issue"] for f in result["findings"])


def test_gosu_named_inline_in_the_dockerfile_counts(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN apt-get install -y gosu\n"
        'ENTRYPOINT ["sh", "-c", "exec gosu app python3 -m app"]\n'
    )
    result = ConfigAuditAgent()._audit_dockerfile(
        dockerfile.read_text(), str(dockerfile)
    )
    assert not any("runs as root" in f["issue"] for f in result["findings"])
