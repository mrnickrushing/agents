"""Prospect report — an editorial pass, not a reskin.

The two properties that matter: nothing that maps the codebase (paths, line
numbers, rule internals) reaches the shareable body, and nothing is inflated
— every count is unmodified scanner output and an empty report says so.
"""

import json

from agents.prospect_report import render_html, summarize


def _report(results):
    return {"results": results, "coverage": {"files_scanned": 42}}


def _entry(tool, file, findings):
    return {"file": file, "agent": "x", "tool": tool, "result": {"findings": findings}}


SCAN = _report([
    _entry("audit_hardcoded_secrets", "src/config.ts", [
        {"severity": "CRITICAL", "issue": "Hardcoded API Key detected", "line": 14},
    ]),
    _entry("audit_sql_injection", "src/db/users.py", [
        {"severity": "HIGH", "issue": "string-built query", "line": 88},
        {"severity": "HIGH", "issue": "string-built query", "line": 102},
    ]),
    _entry("audit_workflow", ".github/workflows/ci.yml", [
        {"severity": "LOW", "issue": "`actions/checkout@v4` is pinned to a mutable tag, not a commit SHA"},
    ]),
])


def test_counts_are_unmodified_scanner_output():
    s = summarize(SCAN)
    assert s["total"] == 4
    assert dict(s["severities"]) == {"CRITICAL": 1, "HIGH": 2, "LOW": 1}
    assert s["files_with_findings"] == 3
    assert s["files_scanned"] == 42


def test_findings_group_into_themes_with_business_meaning():
    s = summarize(SCAN)
    assert "Credential exposure" in s["themes"]
    assert "Injection & data exposure" in s["themes"]
    assert s["themes"]["Injection & data exposure"]["count"] == 2


def test_no_paths_lines_or_rule_ids_reach_the_page():
    """The document is designed to be forwarded. Exact coordinates of every
    weakness in a prospect's codebase must not be in it — that is both the
    engagement's value and the prospect's safety."""
    page = render_html(summarize(SCAN), company="Acme Inc")
    for leak in ("src/config.ts", "src/db/users.py", "ci.yml", "line 14", "line 88", "audit_sql_injection",
                 "actions/checkout", "string-built query"):
        assert leak not in page, leak
    # But the real counts are there.
    assert "Acme Inc" in page
    assert "2 finding(s)" in page or "2 high" in page


def test_locations_are_counted_not_named():
    page = render_html(summarize(SCAN), company="Acme")
    assert "across 1 location(s)" in page


def test_an_empty_scan_says_so_rather_than_padding():
    page = render_html(summarize(_report([])), company="Acme")
    assert "No findings" in page
    assert "floor, not a ceiling" in page


def test_unknown_tools_land_in_the_generic_theme():
    scan = _report([_entry("some_future_tool", "x.ts", [{"severity": "MEDIUM", "issue": "thing"}])])
    s = summarize(scan)
    assert "Code quality & robustness" in s["themes"]


def test_severity_legend_prints_meanings():
    page = render_html(summarize(SCAN), company="Acme")
    assert "exploitable now" in page
    assert "hygiene and hardening" in page


def test_page_is_self_contained_and_escaped():
    scan = _report([_entry("audit_xss_patterns", "a.ts", [{"severity": "HIGH", "issue": "x"}])])
    page = render_html(summarize(scan), company="<script>alert(1)</script>")
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "http://" not in page and "https://" not in page
