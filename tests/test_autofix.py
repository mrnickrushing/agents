"""Mechanical remediation.

Three properties carry this file. Dry-run writes nothing, ever — a fixer you
cannot preview is one you have to trust blindly, and this one edits workflow
files. Every fixer is idempotent, so running it twice is a no-op rather than
a slow corruption. And an action tag whose SHA cannot be resolved is left
exactly as it was: rewriting it to a guess would break the workflow while
looking like a security improvement.
"""

import textwrap
from unittest.mock import patch

import pytest

from agents import autofix

SHA = "1" * 40
OTHER_SHA = "2" * 40


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    return tmp_path


def _wf(repo, name, text):
    path = repo / ".github" / "workflows" / name
    path.write_text(textwrap.dedent(text).lstrip())
    return path


# --- dry run writes nothing ------------------------------------------------------

def test_dry_run_never_writes(repo):
    wf = _wf(repo, "ci.yml", """
        on: push
        jobs:
          t:
            steps:
              - uses: actions/checkout@v4
    """)
    (repo / ".env.example").write_text("A=\n")
    (repo / "app.py").write_text('import os\nos.getenv("B_VAR")\n')
    before = {p: p.read_bytes() for p in (wf, repo / ".env.example")}

    with patch.object(autofix, "resolve_tag", return_value=SHA):
        result = autofix.plan(str(repo), apply=False)

    assert result.changes, "it should still report what it would do"
    for path, content in before.items():
        assert path.read_bytes() == content, f"{path} was modified during a dry run"


# --- action pinning ----------------------------------------------------------------

def test_pins_mutable_tags_and_keeps_the_tag_as_a_comment(repo):
    wf = _wf(repo, "ci.yml", """
        permissions: { contents: read }
        jobs:
          t:
            steps:
              - uses: actions/checkout@v4
              - uses: aquasecurity/trivy-action@v0.36.0
    """)
    with patch.object(autofix, "resolve_tag", return_value=SHA):
        changed, unresolved = autofix.pin_actions(str(wf), apply=True)

    text = wf.read_text()
    assert changed == 2 and unresolved == []
    assert f"actions/checkout@{SHA} # v4" in text
    assert f"aquasecurity/trivy-action@{SHA} # v0.36.0" in text


def test_already_pinned_and_local_actions_are_left_alone(repo):
    wf = _wf(repo, "ci.yml", f"""
        jobs:
          t:
            steps:
              - uses: actions/checkout@{OTHER_SHA} # v7
              - uses: ./.github/actions/local
    """)
    before = wf.read_text()
    with patch.object(autofix, "resolve_tag", return_value=SHA):
        changed, _ = autofix.pin_actions(str(wf), apply=True)
    assert changed == 0
    assert wf.read_text() == before


def test_an_unresolvable_tag_is_reported_not_guessed(repo):
    """Rewriting it to a guess would break the workflow while looking like a
    security improvement."""
    wf = _wf(repo, "ci.yml", """
        jobs:
          t:
            steps:
              - uses: someone/deleted-action@v9
    """)
    before = wf.read_text()
    with patch.object(autofix, "resolve_tag", return_value=None):
        changed, unresolved = autofix.pin_actions(str(wf), apply=True)

    assert changed == 0
    assert unresolved == ["someone/deleted-action@v9"]
    assert wf.read_text() == before


# --- workflow permissions ------------------------------------------------------------

def test_adds_top_level_permissions_when_there_are_none(repo):
    wf = _wf(repo, "ci.yml", """
        on: push
        jobs:
          t:
            steps:
              - run: echo hi
    """)
    assert autofix.add_workflow_permissions(str(wf), apply=True) is True
    assert "permissions:\n  contents: read" in wf.read_text()


def test_a_workflow_that_already_scopes_per_job_is_untouched(repo):
    wf = _wf(repo, "ci.yml", """
        on: push
        jobs:
          t:
            permissions:
              contents: read
            steps:
              - run: echo hi
    """)
    before = wf.read_text()
    assert autofix.add_workflow_permissions(str(wf), apply=True) is False
    assert wf.read_text() == before


def test_sarif_jobs_keep_the_permission_their_upload_needs(repo):
    """Restricting the token without this turns a passing security-scan job
    into a failing one — worse than the permissive token it replaced."""
    wf = _wf(repo, "scan.yml", """
        on: push
        jobs:
          build:
            steps:
              - run: make
          scan:
            steps:
              - uses: github/codeql-action/upload-sarif@v3
    """)
    autofix.add_workflow_permissions(str(wf), apply=True)
    text = wf.read_text()

    assert text.index("permissions:\n  contents: read") < text.index("jobs:")
    assert "security-events: write" in text
    # ...on the scanning job only.
    assert text.count("security-events: write") == 1
    assert text.index("security-events: write") > text.index("scan:")


# --- .env.example ---------------------------------------------------------------------

def test_documents_only_undocumented_non_platform_vars(repo):
    (repo / ".env.example").write_text("DATABASE_URL=\n")
    (repo / "app.py").write_text(
        'import os\n'
        'os.getenv("DATABASE_URL")\n'      # already documented
        'os.getenv("REDIS_URL")\n'          # missing -> documented
        'os.getenv("PORT")\n'               # platform-supplied -> ignored
    )
    (repo / "app.test.py").write_text('os.getenv("ONLY_IN_TESTS")\n')   # tests ignored

    missing = autofix.undocumented_env_vars(str(repo / ".env.example"))
    assert missing == ["REDIS_URL"]

    autofix.document_env_vars(str(repo / ".env.example"), missing, apply=True)
    text = (repo / ".env.example").read_text()
    assert "REDIS_URL=" in text
    assert "names, not defaults" in text
    assert "ONLY_IN_TESTS" not in text


def test_node_modules_is_not_scanned_for_env_usage(repo):
    (repo / ".env.example").write_text("A=\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("process.env.SHOULD_BE_IGNORED")
    assert autofix.undocumented_env_vars(str(repo / ".env.example")) == []


# --- compose ------------------------------------------------------------------------------

def test_compose_keeps_todays_behaviour_while_parameterizing(repo):
    """The current literal becomes the default, so anyone running this file
    today sees no change — it just stops being reusable with a real password
    by accident."""
    compose = repo / "docker-compose.yml"
    compose.write_text(textwrap.dedent("""
        services:
          db:
            environment:
              POSTGRES_PASSWORD: errandly
            ports:
              - "5432:5432"
          api:
            environment:
              DATABASE_URL: postgresql://u:errandly@db:5432/x
    """).lstrip())

    notes = autofix.harden_compose(str(compose), apply=True)
    text = compose.read_text()

    assert "${POSTGRES_PASSWORD:-errandly}" in text
    assert '- "127.0.0.1:5432:5432"' in text
    assert "postgresql://u:${POSTGRES_PASSWORD:-errandly}@db:5432/x" in text
    assert notes


def test_compose_already_hardened_is_a_no_op(repo):
    compose = repo / "docker-compose.yml"
    compose.write_text('services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"\n')
    before = compose.read_text()
    assert autofix.harden_compose(str(compose), apply=True) == []
    assert compose.read_text() == before


# --- idempotence + validation ---------------------------------------------------------------

def test_running_twice_changes_nothing_the_second_time(repo):
    _wf(repo, "ci.yml", """
        on: push
        jobs:
          t:
            steps:
              - uses: actions/checkout@v4
    """)
    (repo / ".env.example").write_text("A=\n")
    (repo / "app.py").write_text('import os\nos.getenv("B_VAR")\n')
    (repo / "docker-compose.yml").write_text(
        'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: dev\n'
        '    ports:\n      - "5432:5432"\n')

    with patch.object(autofix, "resolve_tag", return_value=SHA):
        first = autofix.plan(str(repo), apply=True)
        snapshot = {p.name: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
        second = autofix.plan(str(repo), apply=True)

    assert first.changes
    assert second.changes == [], "a second pass must be a no-op"
    assert {p.name: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == snapshot


def test_validate_workflows_catches_broken_yaml(repo):
    _wf(repo, "bad.yml", "jobs:\n  t:\n   - this: [is\n  not: yaml\n")
    problems = autofix.validate_workflows(str(repo))
    assert problems and "bad.yml" in problems[0]


def test_validate_workflows_passes_on_good_yaml(repo):
    _wf(repo, "ok.yml", "on: push\njobs:\n  t:\n    steps:\n      - run: echo\n")
    assert autofix.validate_workflows(str(repo)) == []


def test_kinds_restricts_what_runs(repo):
    _wf(repo, "ci.yml", "on: push\njobs:\n  t:\n    steps:\n      - run: echo\n")
    (repo / "docker-compose.yml").write_text(
        'services:\n  db:\n    ports:\n      - "5432:5432"\n')

    result = autofix.plan(str(repo), apply=False, kinds={"compose"})
    assert {c.kind for c in result.changes} == {"compose"}
