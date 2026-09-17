"""Tests for the graph-indexed PR reviewer and its configuration layer."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap

import pytest

from agents.pr_review import (
    SEVERITIES,
    FileDiff,
    PRReviewAgent,
    ReviewMemory,
    auto_approve_decision,
    build_diagram,
    choose_diagram,
    clear_caches,
    confidence_score,
    parse_unified_diff,
    render_review,
    run_review,
    symbol_changes,
)
from agents.review_config import (
    AutoApprovePolicy,
    ReviewConfig,
    load_review_config,
    matches_glob,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_caches():
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def repo(tmp_path):
    """A small repo that establishes conventions, plus a PR that breaks them."""
    root = tmp_path / "repo"
    (root / "src" / "db").mkdir(parents=True)
    (root / "src" / "api").mkdir(parents=True)
    (root / "tests").mkdir(parents=True)

    (root / "src" / "db" / "users.py").write_text(textwrap.dedent("""\
            import logging
            logger = logging.getLogger(__name__)

            def get_user(conn, user_id):
                return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

            def list_users(conn, limit):
                logger.info("listing users")
                return conn.execute("SELECT * FROM users LIMIT ?", (limit,)).fetchall()
            """))
    (root / "src" / "api" / "billing.py").write_text(textwrap.dedent("""\
            import logging
            from src.db.users import get_user
            logger = logging.getLogger(__name__)

            def charge(conn, user_id):
                user = get_user(conn, user_id)
                logger.info("charging")
                return {"ok": True}
            """))
    (root / "tests" / "test_users.py").write_text(
        "from src.db.users import get_user\ndef test_it():\n    assert get_user\n"
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


BREAKING_DIFF = """\
diff --git a/src/db/users.py b/src/db/users.py
index 1111111..2222222 100644
--- a/src/db/users.py
+++ b/src/db/users.py
@@ -1,9 +1,13 @@
 import logging
 logger = logging.getLogger(__name__)
 
-def get_user(conn, user_id):
+def get_user(conn, user_id, tenant_id):
     return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
 
 def list_users(conn, limit):
     logger.info("listing users")
     return conn.execute("SELECT * FROM users LIMIT ?", (limit,)).fetchall()
+
+def search_users(conn, term):
+    print("searching")
+    return conn.execute(f"SELECT * FROM users WHERE name = '{term}'").fetchall()
"""


# ── Diff parsing ──────────────────────────────────────────────────────────────


def test_parse_unified_diff_tracks_real_line_numbers():
    files = parse_unified_diff(BREAKING_DIFF)
    assert len(files) == 1
    changed = files[0]
    assert changed.path == "src/db/users.py"
    assert changed.status == "modified"

    added = {line.new_lineno: line.text for line in changed.added}
    assert any("tenant_id" in text for text in added.values())
    # The new def replaces line 4, and the appended helper lands after it.
    assert added[4].startswith("def get_user(conn, user_id, tenant_id)")
    assert max(added) > 10


def test_parse_unified_diff_handles_added_and_deleted_files():
    diff = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+def a():
+    return 1
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,1 +0,0 @@
-def b(): ...
"""
    files = {item.path: item for item in parse_unified_diff(diff)}
    assert files["new.py"].status == "added"
    assert files["old.py"].status == "deleted"
    assert len(files["new.py"].added) == 2


def test_parse_unified_diff_is_tolerant_of_junk():
    assert parse_unified_diff("") == []
    assert parse_unified_diff("not a diff at all") == []


def test_binary_and_rename_are_recognised():
    diff = """\
diff --git a/logo.png b/logo.png
index aaa..bbb 100644
Binary files a/logo.png and b/logo.png differ
diff --git a/old/name.py b/new/name.py
similarity index 95%
rename from old/name.py
rename to new/name.py
"""
    files = {item.path: item for item in parse_unified_diff(diff)}
    assert files["logo.png"].binary is True
    assert files["new/name.py"].status == "renamed"


# ── Symbol analysis ───────────────────────────────────────────────────────────


def test_symbol_changes_detects_signature_change_and_addition():
    changed = parse_unified_diff(BREAKING_DIFF)[0]
    changes = {item.name: item for item in symbol_changes(changed)}
    assert changes["get_user"].kind == "signature_changed"
    assert "tenant_id" in changes["get_user"].new_params
    assert changes["search_users"].kind == "added"


def test_default_valued_parameter_is_not_a_breaking_change():
    diff = """\
diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,1 +1,1 @@
-def f(a, b):
+def f(a, b, c=None):
"""
    changes = symbol_changes(parse_unified_diff(diff)[0])
    # `c=None` keeps every existing call site valid, so this is not a re-sign.
    assert [item.kind for item in changes] == ["modified"]


def test_typescript_optional_parameter_is_not_breaking():
    diff = """\
diff --git a/m.ts b/m.ts
--- a/m.ts
+++ b/m.ts
@@ -1,1 +1,1 @@
-export function f(a: string) {
+export function f(a: string, b?: number) {
"""
    changes = symbol_changes(parse_unified_diff(diff)[0])
    assert [item.kind for item in changes] == ["modified"]


# ── End-to-end review ─────────────────────────────────────────────────────────


def test_review_flags_breaking_change_with_caller_evidence(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    assert result["reviewed"] is True

    breaking = [
        item for item in result["findings"] if item["category"] == "breaking_change"
    ]
    assert breaking, "a required-parameter change with live callers must be reported"
    finding = breaking[0]
    assert finding["severity"] == "P0"
    assert finding["reviewer"] == "impact"
    # The caller lives outside the diff — that is the whole point of the graph.
    assert any("billing.py" in item for item in finding["evidence"])


def test_review_flags_sql_interpolation(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    sql = [item for item in result["findings"] if item["category"] == "sql_injection"]
    assert sql, "interpolated SQL must be flagged"
    assert sql[0]["severity"] == "P0"
    assert sql[0]["reviewer"] == "security"


def test_confidence_score_reflects_severity(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    assert result["confidence"]["score"] <= 2
    assert result["confidence"]["verdict"] in ("Needs rework", "Major rethink needed")


def test_clean_diff_scores_full_marks(repo):
    diff = """\
diff --git a/src/db/users.py b/src/db/users.py
--- a/src/db/users.py
+++ b/src/db/users.py
@@ -6,3 +6,4 @@ def get_user(conn, user_id):
 def list_users(conn, limit):
     logger.info("listing users")
     return conn.execute("SELECT * FROM users LIMIT ?", (limit,)).fetchall()
+    # trailing note
"""
    result = run_review(repo_path=str(repo), diff=diff)
    assert result["findings"] == []
    assert result["confidence"]["score"] == 5
    assert result["confidence"]["verdict"] == "Merge"


def test_review_runs_without_a_graph(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF, use_graph=False)
    assert result["reviewed"] is True
    assert result["graph"] == {"indexed": False}
    # Without the graph there is no cross-file evidence, so no breaking-change call.
    assert not [
        item for item in result["findings"] if item["category"] == "breaking_change"
    ]


def test_every_swarm_member_reports_status(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    from agents.pr_review import SWARM

    assert set(result["swarm"]) == {name for name, _ in SWARM}
    assert all(entry["ok"] for entry in result["swarm"].values())


# ── Configuration ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("**/*.generated.*", "src/api/types.generated.ts", True),
        ("dist/**", "dist/main.js", True),
        ("dist/**", "src/main.js", False),
        ("*.md", "docs/readme.md", True),
        ("src/api/**/*.ts", "src/api/v1/billing.ts", True),
        ("src/api/**/*.ts", "src/web/app.ts", False),
        ("src/**/*.{ts,tsx}", "src/ui/Button.tsx", True),
        ("a/**/b", "a/b", True),
        ("?oo.ts", "foo.ts", True),
        ("vendor/", "vendor/lib/x.go", True),
        ("dependabot[bot]", "dependabot[bot]", True),
    ],
)
def test_glob_matching(pattern, path, expected):
    assert matches_glob(pattern, path) is expected


def test_root_config_is_loaded(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps(
            {
                "strictness": 3,
                "commentTypes": ["logic"],
                "ignorePatterns": "dist/**\n*.md",
                "excludeAuthors": ["dependabot[bot]"],
            }
        )
    )
    config = load_review_config(str(tmp_path))
    assert config.strictness == 3
    assert config.comment_types == ["logic"]
    assert config.is_ignored("dist/app.js") is True
    assert config.is_ignored("src/app.js") is False


def test_nested_config_tightens_but_rules_accumulate(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps(
            {
                "strictness": 1,
                "customContext": {
                    "rules": [
                        {
                            "rule": "Endpoints need rate limiting",
                            "id": "rl",
                            "scope": ["src/api/**"],
                        }
                    ]
                },
            }
        )
    )
    nested = tmp_path / "src" / "api" / ".greptile"
    nested.mkdir(parents=True)
    (nested / "config.json").write_text(
        json.dumps({"strictness": 3, "rules": [{"rule": "No raw SQL", "id": "sql"}]})
    )
    (nested / "rules.md").write_text("# API rules\nValidate at the boundary.")

    config = load_review_config(str(tmp_path))
    assert config.strictness == 1

    scoped = config.for_path("src/api/billing.ts")
    assert scoped.strictness == 3
    assert {rule.id for rule in scoped.rules_for("src/api/billing.ts")} == {"rl", "sql"}
    assert scoped.prose_rules  # rules.md is picked up

    # A file outside the nested directory keeps the root settings.
    elsewhere = config.for_path("src/web/app.ts")
    assert elsewhere.strictness == 1
    assert elsewhere.rules_for("src/web/app.ts") == []


def test_greptile_folder_takes_precedence_over_root_json(tmp_path):
    (tmp_path / "greptile.json").write_text(json.dumps({"strictness": 1}))
    (tmp_path / ".greptile").mkdir()
    (tmp_path / ".greptile" / "config.json").write_text(json.dumps({"strictness": 3}))
    assert load_review_config(str(tmp_path)).strictness == 3


def test_scoped_rule_does_not_apply_outside_its_scope(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps({"rules": [{"rule": "x", "id": "r", "scope": ["src/api/**"]}]})
    )
    config = load_review_config(str(tmp_path))
    assert [rule.id for rule in config.rules_for("src/api/a.ts")] == ["r"]
    assert config.rules_for("src/web/a.ts") == []


def test_disabled_rule_is_dropped(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps({"rules": [{"rule": "x", "id": "r"}], "disabledRules": ["r"]})
    )
    assert load_review_config(str(tmp_path)).rules_for("a.ts") == []


@pytest.mark.parametrize(
    "pr,expected",
    [
        ({"event": "open", "user": {"login": "nick"}, "base": {"ref": "main"}}, True),
        (
            {
                "event": "open",
                "user": {"login": "dependabot[bot]"},
                "base": {"ref": "main"},
            },
            False,
        ),
        ({"event": "push", "user": {"login": "nick"}, "base": {"ref": "main"}}, False),
        (
            {
                "event": "open",
                "draft": True,
                "user": {"login": "nick"},
                "base": {"ref": "main"},
            },
            False,
        ),
        (
            {
                "event": "open",
                "user": {"login": "nick"},
                "base": {"ref": "main"},
                "title": "WIP: skip",
            },
            False,
        ),
    ],
)
def test_pr_scope_filters(tmp_path, pr, expected):
    (tmp_path / "greptile.json").write_text(
        json.dumps(
            {
                "autoReview": ["open"],
                "excludeAuthors": ["dependabot[bot]"],
                "ignoreKeywords": "WIP",
            }
        )
    )
    config = load_review_config(str(tmp_path))
    assert config.should_review(pr)[0] is expected


def test_out_of_scope_pr_is_not_reviewed(repo):
    (repo / "greptile.json").write_text(json.dumps({"excludeAuthors": ["bot"]}))
    result = run_review(
        repo_path=str(repo),
        diff=BREAKING_DIFF,
        pull_request={
            "event": "open",
            "user": {"login": "bot"},
            "base": {"ref": "main"},
        },
    )
    assert result["reviewed"] is False
    assert "excludeAuthors" in result["skipped_reason"]
    assert result["findings"] == []


def test_ignore_patterns_exclude_a_file_from_review(repo):
    (repo / "greptile.json").write_text(json.dumps({"ignorePatterns": "src/db/**"}))
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    assert result["files_reviewed"] == 0
    assert result["findings"] == []


# ── Strictness ────────────────────────────────────────────────────────────────


def test_strictness_widens_and_narrows_the_review(repo):
    verbose = run_review(
        repo_path=str(repo), diff=BREAKING_DIFF, overrides={"strictness": 1}
    )
    balanced = run_review(
        repo_path=str(repo), diff=BREAKING_DIFF, overrides={"strictness": 2}
    )
    critical = run_review(
        repo_path=str(repo), diff=BREAKING_DIFF, overrides={"strictness": 3}
    )

    assert (
        len(verbose["findings"])
        >= len(balanced["findings"])
        >= len(critical["findings"])
    )
    # Critical-only never surfaces a P2.
    assert all(item["severity"] != "P2" for item in critical["findings"])

    # …and never loses a P0.
    def criticals(result):
        return {
            item["title"] for item in result["findings"] if item["severity"] == "P0"
        }

    assert criticals(verbose) == criticals(critical)


def test_comment_types_filter_the_review(repo):
    result = run_review(
        repo_path=str(repo),
        diff=BREAKING_DIFF,
        overrides={"strictness": 1, "commentTypes": ["style"]},
    )
    assert result["findings"]
    assert {item["comment_type"] for item in result["findings"]} == {"style"}


# ── Learning ──────────────────────────────────────────────────────────────────


@pytest.fixture
def memory(tmp_path):
    store = ReviewMemory(str(tmp_path / "memory.db"))
    yield store
    store.close()


def test_repeated_dismissals_suppress_a_style_category(memory, tmp_path):
    project = str(tmp_path)
    finding = {"category": "convention:print_debug", "severity": "P2"}
    for _ in range(2):
        memory.record(project, finding, "ignored")
    assert memory.suppressed_categories(project) == set()

    memory.record(project, finding, "ignored")
    assert "convention:print_debug" in memory.suppressed_categories(project)


def test_a_category_the_team_acts_on_is_not_suppressed(memory, tmp_path):
    project = str(tmp_path)
    finding = {"category": "convention:print_debug", "severity": "P2"}
    for _ in range(3):
        memory.record(project, finding, "ignored")
    for _ in range(3):
        memory.record(project, finding, "addressed")
    # Half the comments were acted on — that is not a category to go quiet on.
    assert memory.suppressed_categories(project) == set()


def test_security_categories_are_never_suppressed(memory, tmp_path):
    project = str(tmp_path)
    for category in ("sql_injection", "hardcoded_secrets", "breaking_change"):
        for _ in range(10):
            memory.record(project, {"category": category}, "ignored")
    assert memory.suppressed_categories(project) == set()


def test_suppression_never_drops_a_p0(memory, tmp_path):
    from agents.pr_review import ReviewFinding

    project = str(tmp_path)
    for _ in range(5):
        memory.record(project, {"category": "test_coverage"}, "ignored")

    findings = [
        ReviewFinding(
            file="a.py",
            line=1,
            severity="P0",
            comment_type="logic",
            title="critical",
            category="test_coverage",
        ),
        ReviewFinding(
            file="a.py",
            line=2,
            severity="P2",
            comment_type="style",
            title="nit",
            category="test_coverage",
        ),
    ]
    kept, suppressed = memory.apply(project, findings)
    assert [item.severity for item in kept] == ["P0"]
    assert suppressed == ["test_coverage"]


def test_invalid_verdict_is_rejected(memory, tmp_path):
    with pytest.raises(ValueError):
        memory.record(str(tmp_path), {"category": "x"}, "maybe")


def test_review_honours_learned_suppression(repo, memory):
    project = os.path.realpath(str(repo))
    for _ in range(4):
        memory.record(project, {"category": "convention:print_debug"}, "ignored")

    result = run_review(
        repo_path=str(repo),
        diff=BREAKING_DIFF,
        overrides={"strictness": 1},
        memory=memory,
    )
    categories = {item["category"] for item in result["findings"]}
    assert "convention:print_debug" not in categories
    assert "sql_injection" in categories  # security survives
    assert result["suppressed_categories"] == ["convention:print_debug"]


# ── Auto-approve ──────────────────────────────────────────────────────────────


def _clean_score():
    return confidence_score([], [])


def test_auto_approve_is_off_by_default():
    decision = auto_approve_decision(ReviewConfig(), [], _clean_score(), [])
    assert decision["approved"] is False
    assert "not enabled" in decision["reason"]


def test_auto_approve_needs_a_clean_five(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps({"autoApprove": {"enabled": True, "riskCeiling": "low"}})
    )
    config = load_review_config(str(tmp_path))
    assert auto_approve_decision(config, [], _clean_score(), [])["approved"] is True

    from agents.pr_review import ReviewFinding

    finding = ReviewFinding(
        file="a.py", line=1, severity="P2", comment_type="style", title="nit"
    )
    score = confidence_score([finding], [])
    decision = auto_approve_decision(config, [finding], score, [])
    assert decision["approved"] is False
    assert "5/5" in decision["reason"]


def test_auto_approve_respects_excluded_paths(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps(
            {
                "autoApprove": {
                    "enabled": True,
                    "filters": {"excludePaths": ["src/payments/**"]},
                }
            }
        )
    )
    config = load_review_config(str(tmp_path))
    files = [FileDiff(path="src/payments/charge.ts")]
    decision = auto_approve_decision(config, [], _clean_score(), files)
    assert decision["approved"] is False
    assert "excludePaths" in decision["reason"]


def test_nested_config_can_only_tighten_auto_approve(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps({"autoApprove": {"enabled": True, "riskCeiling": "high"}})
    )
    nested = tmp_path / "src" / "api" / ".greptile"
    nested.mkdir(parents=True)
    (nested / "config.json").write_text(
        json.dumps({"autoApprove": {"enabled": True, "riskCeiling": "low"}})
    )
    root = load_review_config(str(tmp_path))
    assert root.auto_approve.risk_ceiling == "high"
    assert root.for_path("src/api/x.ts").auto_approve.risk_ceiling == "low"


def test_nested_config_cannot_re_enable_auto_approve(tmp_path):
    (tmp_path / "greptile.json").write_text(
        json.dumps({"autoApprove": {"enabled": False}})
    )
    nested = tmp_path / "src" / ".greptile"
    nested.mkdir(parents=True)
    (nested / "config.json").write_text(json.dumps({"autoApprove": {"enabled": True}}))
    config = load_review_config(str(tmp_path))
    assert config.for_path("src/x.ts").auto_approve.enabled is False


def test_auto_approve_policy_merge_unions_exclusions():
    parent = AutoApprovePolicy(
        enabled=True, risk_ceiling="high", exclude_paths=["a/**"]
    )
    child = AutoApprovePolicy(
        enabled=True, risk_ceiling="medium", exclude_paths=["b/**"]
    )
    merged = parent.merge(child)
    assert merged.risk_ceiling == "medium"
    assert merged.exclude_paths == ["a/**", "b/**"]


# ── Scoring ───────────────────────────────────────────────────────────────────


def test_a_long_tail_of_nits_cannot_outweigh_one_critical():
    from agents.pr_review import ReviewFinding

    nits = [
        ReviewFinding(
            file="a.py",
            line=index,
            severity="P2",
            comment_type="style",
            title=f"nit {index}",
        )
        for index in range(40)
    ]
    critical = [
        ReviewFinding(
            file="a.py", line=1, severity="P0", comment_type="logic", title="rce"
        )
    ]
    assert (
        confidence_score(nits, [])["score"] >= confidence_score(critical, [])["score"]
    )


def test_score_is_clamped_to_the_scale():
    from agents.pr_review import ReviewFinding

    many = [
        ReviewFinding(
            file="a.py",
            line=index,
            severity="P0",
            comment_type="logic",
            title=f"bug {index}",
        )
        for index in range(50)
    ]
    score = confidence_score(many, [])
    assert 0 <= score["score"] <= 5


# ── Diagrams ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "diff_body,expected",
    [
        ('+export const users = pgTable("users", {\n+  id: uuid("id"),\n', "er"),
        (
            '+router.post("/charge", handler)\n+  await stripe.charges.create()\n',
            "sequence",
        ),
        ("+class Foo extends Bar {\n+  run() {}\n+class Baz extends Bar {\n", "class"),
        ("+def helper(a):\n+    return a\n", "flow"),
    ],
)
def test_diagram_kind_follows_the_change(diff_body, expected):
    diff = (
        "diff --git a/f.ts b/f.ts\n--- a/f.ts\n+++ b/f.ts\n@@ -1,1 +1,4 @@\n"
        + diff_body
    )
    files = parse_unified_diff(diff)
    assert choose_diagram(files) == expected


def test_er_diagram_names_the_table():
    diff = (
        "diff --git a/schema.ts b/schema.ts\n--- a/schema.ts\n+++ b/schema.ts\n"
        '@@ -1,1 +1,4 @@\n+export const users = pgTable("users", {\n'
        '+  id: uuid("id"),\n+  email: text("email"),\n+});\n'
    )
    diagram = build_diagram(parse_unified_diff(diff))
    assert diagram["kind"] == "er"
    assert diagram["mermaid"].startswith("erDiagram")
    assert "users" in diagram["mermaid"]
    assert "email" in diagram["mermaid"]


def test_diagram_is_empty_when_nothing_fits():
    diff = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,1 +1,1 @@\n+hello\n"
    assert build_diagram(parse_unified_diff(diff)) == {}


# ── Rendering ─────────────────────────────────────────────────────────────────


def test_markdown_carries_every_section(repo):
    result = run_review(repo_path=str(repo), diff=BREAKING_DIFF)
    markdown = result["markdown"]
    for heading in (
        "Review summary",
        "Confidence score",
        "Issues found",
        "Files changed",
        "Inline comments",
    ):
        assert heading in markdown
    assert "P0" in markdown
    assert "src/db/users.py" in markdown


def test_sections_can_be_collapsed(repo):
    result = run_review(
        repo_path=str(repo),
        diff=BREAKING_DIFF,
        overrides={
            "summarySection": {
                "included": True,
                "collapsible": True,
                "defaultOpen": False,
            }
        },
    )
    assert "<details>\n<summary><b>Review summary</b></summary>" in result["markdown"]


def test_sections_can_be_turned_off(repo):
    result = run_review(
        repo_path=str(repo),
        diff=BREAKING_DIFF,
        overrides={"includeConfidenceScore": False, "includeSequenceDiagram": False},
    )
    assert "Confidence score" not in result["markdown"]
    assert "```mermaid" not in result["markdown"]


def test_update_summary_only_drops_inline_comments(repo):
    result = run_review(
        repo_path=str(repo), diff=BREAKING_DIFF, overrides={"updateSummaryOnly": True}
    )
    assert "Inline comments" not in result["markdown"]
    assert result["findings"], "findings are still reported in the payload"


def test_footer_can_be_hidden(repo):
    result = run_review(
        repo_path=str(repo), diff=BREAKING_DIFF, overrides={"hideFooter": True}
    )
    assert "swarm:" not in result["markdown"]


def test_skipped_review_renders_its_reason():
    config = ReviewConfig()
    markdown = render_review(
        {"reviewed": False, "skipped_reason": "PR is a draft"}, config
    )
    assert "draft" in markdown


# ── Agent surface ─────────────────────────────────────────────────────────────


def test_agent_exposes_its_tools_without_an_api_key():
    agent = PRReviewAgent()
    names = {tool["name"] for tool in agent._define_tools()}
    assert names == set(agent._bind_tool_handlers())
    assert "review_pull_request" in names


def test_agent_reviews_a_diff_directly(repo):
    agent = PRReviewAgent()
    result = agent.review_pull_request(
        repo_path=str(repo), diff=BREAKING_DIFF, use_memory=False
    )
    assert result["reviewed"] is True
    assert any(item["severity"] == "P0" for item in result["findings"])


def test_explain_impact_traces_callers(repo):
    agent = PRReviewAgent()
    result = agent._explain_impact("get_user", repo_path=str(repo))
    assert result["caller_count"] >= 1
    assert any("billing.py" in site for site in result["called_by"])
    assert result["blast_radius"] in ("narrow", "moderate", "wide")


def test_index_codebase_reports_what_it_indexed(repo):
    result = PRReviewAgent()._index_codebase(repo_path=str(repo))
    assert result["indexed"] is True
    assert result["symbols"] > 0


def test_check_review_scope_explains_a_rejection(repo):
    (repo / "greptile.json").write_text(json.dumps({"excludeAuthors": ["bot"]}))
    result = PRReviewAgent()._check_review_scope(
        {"event": "open", "user": {"login": "bot"}, "base": {"ref": "main"}},
        repo_path=str(repo),
    )
    assert result["in_scope"] is False
    assert "excludeAuthors" in result["reason"]


def test_severity_ladder_is_ordered():
    assert SEVERITIES == ("P0", "P1", "P2")


# ── Injected SQL ──────────────────────────────────────────────────────────────


def _sql_findings(body):
    from agents.pr_review import _injected_sql

    diff = "diff --git a/s.py b/s.py\n--- a/s.py\n+++ b/s.py\n@@ -1,1 +1,9 @@\n" + body
    return _injected_sql(parse_unified_diff(diff)[0])


@pytest.mark.parametrize(
    "line",
    [
        '+conn.execute("SELECT * FROM users WHERE id = ?", (uid,))',
        '+db.query("INSERT INTO users (email) VALUES ($1)", [email])',
        # `%s` with a tuple is the bound-parameter form, not interpolation.
        '+cur.execute("UPDATE t SET a = %s WHERE b = %s", (a, b))',
        '+cur.execute("DELETE FROM t WHERE id = :tid", {"tid": tid})',
        # An f-string that is not a query at all.
        '+log.info(f"Last case update recorded on {when}")',
    ],
)
def test_bound_parameters_are_not_flagged(line):
    assert _sql_findings(line + "\n") == []


@pytest.mark.parametrize(
    "line",
    [
        '+cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
        '+db.query("SELECT * FROM t WHERE a = \'" + val + "\'")',
        '+cur.execute("SELECT * FROM t WHERE a = {}".format(val))',
        '+cur.execute("UPDATE t SET a = %s WHERE b = 1" % val)',
        "+db.query(`SELECT * FROM t WHERE a = ${val}`)",
    ],
)
def test_interpolated_sql_is_flagged_as_critical(line):
    findings = _sql_findings(line + "\n")
    assert len(findings) == 1
    assert findings[0].severity == "P0"
    assert findings[0].category == "sql_injection"


def test_injected_sql_does_not_need_corpus_evidence(tmp_path):
    """Injection is flagged even in a repo with nothing to compare against.

    The conventions reviewer stays quiet without evidence the repo does it the
    safe way. A P0 security defect must not inherit that reticence.
    """
    root = tmp_path / "bare"
    root.mkdir()
    diff = (
        "diff --git a/only.py b/only.py\nnew file mode 100644\n--- /dev/null\n"
        "+++ b/only.py\n@@ -0,0 +1,2 @@\n"
        '+def f(conn, name):\n+    return conn.execute(f"SELECT * FROM t WHERE n = {name}")\n'
    )
    result = run_review(repo_path=str(root), diff=diff)
    assert any(item["category"] == "sql_injection" for item in result["findings"])


def _review_new_file(tmp_path, body):
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    diff = (
        "diff --git a/q.py b/q.py\nnew file mode 100644\n--- /dev/null\n+++ b/q.py\n"
        f"@@ -0,0 +1,{body.count('+')} @@\n" + body
    )
    return run_review(repo_path=str(root), diff=diff, overrides={"strictness": 1})


def test_one_interpolated_query_reports_once(tmp_path):
    """`_injected_sql` and the shared detector both see a same-line query.

    Before the shared detector was fixed it saw nothing here, so both could
    not fire at once. Now they can, and a reviewer should still get one
    comment — the better-anchored P0, not that plus a P2 restating it.
    """
    result = _review_new_file(
        tmp_path,
        "+def f(conn, name):\n"
        "+    return conn.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
    )
    sql = [item for item in result["findings"] if item["category"] == "sql_injection"]
    assert len(sql) == 1
    assert sql[0]["severity"] == "P0"
    assert sql[0]["line"] == 2  # anchored on the query, not the function


def test_query_built_then_executed_is_still_caught(tmp_path):
    """The reach the shared detector adds: `_injected_sql` needs the query
    and the call on one line, and this splits them."""
    result = _review_new_file(
        tmp_path,
        "+def f(conn, name):\n"
        '+    sql = f"SELECT * FROM t WHERE n = {name}"\n'
        "+    return conn.execute(sql)\n",
    )
    assert any(item["category"] == "sql_injection" for item in result["findings"])
