import json
import sys

from agents.cli import (
    MAX_FILE_BYTES,
    _entry_findings,
    _format_report,
    _highest_active_severity_at_or_above,
    _inline_local_imports,
    _partition_active_dismissed,
    _run_scan,
)


def _write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_one_shot_scan_exercises_every_scannable_agent(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "5.0.0"}}))
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, ".github/workflows/test.yml", "name: test\n")
    _write(tmp_path, "tests/smoke.test.ts", "it('works', () => {});\n")
    _write(
        tmp_path,
        "src/auth.ts",
        "export async function rotate(refresh_token) { return refresh_token; }\n",
    )
    _write(
        tmp_path,
        "src/billing.ts",
        "const event = stripe.webhooks.constructEvent(req.body, sig, secret);\nres.status(200).send();\n",
    )
    _write(
        tmp_path,
        "src/routes.ts",
        "router.get('/items', async (_req, res) => { const rows = await db.select().from(items); res.json(rows); });\n",
    )
    _write(
        tmp_path,
        "src/schema.ts",
        "export const posts = pgTable('posts', { id: uuid('id').primaryKey(), userId: uuid('user_id').references(() => users.id) });\n",
    )
    _write(
        tmp_path,
        "src/App.tsx",
        "import { useState } from 'react';\nexport default function App(){ const [x] = useState(1); return <img src='x' />; }\n",
    )
    _write(
        tmp_path,
        "src/monitor.ts",
        "Sentry.init({ dsn: process.env.SENTRY_DSN, sendDefaultPii: false, tracesSampleRate: 0.2 });\n",
    )
    _write(
        tmp_path,
        "eas.json",
        json.dumps({"build": {"production": {"autoIncrement": True}}, "submit": {"production": {}}}),
    )
    _write(tmp_path, "Dockerfile", "FROM node:latest\nRUN npm install\nCMD [\"node\", \"server.js\"]\n")

    report = _run_scan(str(tmp_path), None)

    assert report["coverage"]["tool_errors"] == 0
    assert set(report["coverage"]["agents_exercised"]) == {
        "api_architect",
        "auth_security",
        "code_review",
        "config_audit",
        "database_architect",
        "flow_audit",
        "frontend_performance",
        "iac_security",
        "infra_monitor",
        "mobile_deploy",
        "railway_deploy",
        "security_audit",
        "supply_chain_audit",
        "stripe_billing",
        "ui_generation",
    }
    assert report["coverage"]["verification_gaps"] == []


def test_dependency_free_package_does_not_require_a_lockfile(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"name": "tool", "scripts": {"test": "true"}}))

    report = _run_scan(str(tmp_path), None)

    assert not any("lockfile" in gap for gap in report["coverage"]["verification_gaps"])


def test_package_dependencies_without_a_lockfile_are_reported(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"example": "^1.0.0"}}))

    report = _run_scan(str(tmp_path), None)

    assert any("lockfile" in gap for gap in report["coverage"]["verification_gaps"])


def test_roblox_luau_and_validation_scripts_receive_targeted_checks(tmp_path):
    _write(tmp_path, "src/module.luau", "--!strict\nreturn table.freeze({ ready = true })\n")
    _write(tmp_path, "types/standard.d.luau", "declare function task_wait(): ()\n")
    _write(tmp_path, "scripts/typecheck.mjs", "import { spawnSync } from 'node:child_process';\nspawnSync('luau-lsp', []);\n")

    report = _run_scan(str(tmp_path), None)

    assert "roblox_audit" in report["coverage"]["agents_exercised"]
    assert report["coverage"]["files_without_targeted_checks"] == []


def test_runtime_verification_is_explicit_and_records_result(tmp_path):
    report = _run_scan(
        str(tmp_path),
        None,
        runtime=True,
        runtime_command=[sys.executable, "-c", "print('runtime ok')"],
    )

    runtime = report["coverage"]["runtime_verification"]
    assert runtime["status"] == "passed"
    assert "runtime ok" in runtime["output_tail"]
    assert report["coverage"]["confidence"] == "static-plus-runtime-verified"


def test_discovery_ignores_dangerous_api_names_in_comments_and_strings(tmp_path):
    _write(
        tmp_path,
        "scanner.py",
        '''\n# Never call eval(user_input) or jwt.verify(token, key) here.\nPATTERNS = ["stripe.webhooks.constructEvent", "Sentry.init(", "CORSMiddleware"]\ndef harmless():\n    return PATTERNS\n''',
    )

    report = _run_scan(str(tmp_path), None)

    assert report["coverage"]["checks_run"] == 0
    assert report["results"] == []


def test_integrity_checks_report_syntax_json_and_merge_conflicts(tmp_path):
    _write(tmp_path, "broken.py", "def nope(:\n    pass\n")
    _write(tmp_path, "broken.json", '{"missing": }')
    _write(tmp_path, "conflict.ts", "<<<<<<< HEAD\nconst x = 1;\n=======\nconst x = 2;\n>>>>>>> branch\n")

    report = _run_scan(str(tmp_path), None)
    issues = [finding["issue"] for entry in report["results"] for finding in _entry_findings(entry)]

    assert any("Python syntax error" in issue for issue in issues)
    assert any("Invalid JSON" in issue for issue in issues)
    assert any("merge-conflict" in issue for issue in issues)


def test_large_files_are_visible_as_coverage_gaps(tmp_path):
    _write(tmp_path, "too-large.ts", "x" * (MAX_FILE_BYTES + 1))

    report = _run_scan(str(tmp_path), None)

    assert report["coverage"]["confidence"] == "incomplete"
    assert report["coverage"]["skipped_files"][0]["reason"] == "file_too_large"


def test_generated_dist_variant_directories_are_not_scanned(tmp_path):
    _write(tmp_path, "dist-marketing/bundle.js", "target.innerHTML = userInput;")
    _write(tmp_path, "src/safe.ts", "export const safe = true;")

    report = _run_scan(str(tmp_path), None)

    assert all(not entry["file"].startswith("dist-marketing/") for entry in report["results"])
    assert report["coverage"]["files_considered"] == 1


def test_generated_artifacts_directories_are_not_scanned(tmp_path):
    _write(tmp_path, "artifacts/api/routes.ts", "target.innerHTML = userInput;")
    _write(tmp_path, "src/safe.ts", "export const safe = true;")

    report = _run_scan(str(tmp_path), None)

    assert report["coverage"]["files_considered"] == 1


def test_large_binary_asset_does_not_make_text_scan_incomplete(tmp_path):
    _write(tmp_path, "assets/icon.png", "x" * (MAX_FILE_BYTES + 1))
    _write(tmp_path, "src/safe.ts", "export const safe = true;")

    report = _run_scan(str(tmp_path), None)

    assert report["coverage"]["skipped_files"] == []


def test_human_report_does_not_hide_static_scan_boundary(tmp_path):
    _write(tmp_path, "src/plain.ts", "export const plain = true;")

    rendered = _format_report(_run_scan(str(tmp_path), None))

    assert "Production code files with no specialized check: 1" in rendered
    assert "Runtime verification: not requested" in rendered


def test_typescript_source_resolves_from_esm_js_import(tmp_path):
    route = _write(tmp_path, "src/routes/auth.ts", "import { verify } from '../lib/apple.js';\nverify();")
    _write(tmp_path, "src/lib/apple.ts", "export const verify = () => 'jwks';")

    combined = _inline_local_imports(str(route), route.read_text(), str(tmp_path))

    assert "export const verify" in combined


def test_python_parent_relative_import_is_inlined(tmp_path):
    route = _write(tmp_path, "app/routes/auth.py", "from ..security.apple import verify\nverify()")
    _write(tmp_path, "app/security/apple.py", "def verify(): return 'jwks'")

    combined = _inline_local_imports(str(route), route.read_text(), str(tmp_path))

    assert "def verify" in combined


def test_apple_review_sees_local_verifier_context(tmp_path):
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, ".github/workflows/test.yml", "name: test")
    _write(tmp_path, "tests/auth.test.ts", "it('works', () => {});")
    _write(
        tmp_path,
        "src/routes/auth.ts",
        "import { verifyAppleIdentityToken } from '../lib/apple.js';\n"
        "await verifyAppleIdentityToken(identityToken, rawNonce);",
    )
    _write(
        tmp_path,
        "src/lib/apple.ts",
        "createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'));\n"
        "jwtVerify(identityToken, jwks, { issuer: 'https://appleid.apple.com', audience });\n"
        "if (payload.nonce !== hash(rawNonce)) throw new Error('nonce');",
    )

    report = _run_scan(str(tmp_path), ["auth_security"])
    issues = [
        finding["issue"]
        for entry in report["results"]
        for finding in entry["result"].get("findings", [])
    ]

    assert not any("Apple" in issue or "nonce" in issue or "JWKS" in issue for issue in issues)


def _synthetic_report(*entries):
    return {"project": ".", "results": list(entries), "summary": {}, "coverage": {}}


def _entry(severity, verdict=None, feedback_verdict=None):
    entry = {
        "file": "src/x.ts",
        "agent": "security_audit",
        "tool": "audit_sql_injection",
        "source_hash": "abc",
        "result": {"findings": [{"severity": severity, "issue": "example finding"}]},
    }
    if verdict:
        entry["triage"] = {"verdict": verdict, "reason": "because"}
    if feedback_verdict:
        entry["feedback"] = {"verdict": feedback_verdict, "reason": "because", "source": "human"}
    return entry


def test_fail_on_trips_for_active_finding_at_or_above_threshold():
    report = _synthetic_report(_entry("HIGH"))

    assert _highest_active_severity_at_or_above(report, "HIGH") is True
    assert _highest_active_severity_at_or_above(report, "CRITICAL") is False


def test_fail_on_ignores_finding_below_threshold():
    report = _synthetic_report(_entry("LOW"))

    assert _highest_active_severity_at_or_above(report, "HIGH") is False


def test_fail_on_excludes_triage_dismissed_findings():
    report = _synthetic_report(_entry("CRITICAL", verdict="FALSE_POSITIVE"))

    assert _highest_active_severity_at_or_above(report, "LOW") is False


def test_fail_on_excludes_learned_feedback_dismissed_findings_even_if_triage_disagrees():
    # Human feedback is authoritative over triage per _effective_entry_verdict.
    report = _synthetic_report(
        _entry("CRITICAL", verdict="CONFIRMED", feedback_verdict="FALSE_POSITIVE")
    )

    assert _highest_active_severity_at_or_above(report, "LOW") is False


def test_partition_active_dismissed_splits_on_effective_verdict():
    active_entry = _entry("HIGH")
    dismissed_entry = _entry("HIGH", verdict="FALSE_POSITIVE")
    report = _synthetic_report(active_entry, dismissed_entry)

    active, dismissed = _partition_active_dismissed(report["results"])

    assert active == [active_entry]
    assert dismissed == [dismissed_entry]


def _mixed_verdict_entry():
    # Mirrors how triage_report()/apply_feedback() actually annotate a
    # multi-finding entry: each finding gets its own verdict, and the
    # entry-level verdict is CONFIRMED because *any* finding was confirmed
    # — even though the HIGH finding specifically was dismissed.
    return {
        "file": "src/x.ts",
        "agent": "security_audit",
        "tool": "audit_sql_injection",
        "source_hash": "abc",
        "result": {
            "findings": [
                {
                    "severity": "HIGH",
                    "issue": "dismissed high finding",
                    "triage": {"verdict": "FALSE_POSITIVE", "reason": "handled elsewhere"},
                },
                {
                    "severity": "LOW",
                    "issue": "confirmed low finding",
                    "triage": {"verdict": "CONFIRMED", "reason": "real"},
                },
            ]
        },
        "triage": {"verdict": "CONFIRMED", "reason": "real"},
    }


def test_fail_on_evaluates_dismissals_per_finding_not_per_entry():
    # Regression test: a naive per-entry check would see the entry's
    # aggregate CONFIRMED verdict and treat the individually-dismissed HIGH
    # finding as still active, incorrectly tripping --fail-on HIGH.
    report = _synthetic_report(_mixed_verdict_entry())

    assert _highest_active_severity_at_or_above(report, "HIGH") is False
    assert _highest_active_severity_at_or_above(report, "LOW") is True


def test_fail_on_finding_level_feedback_overrides_finding_level_triage():
    entry = {
        "file": "src/x.ts",
        "agent": "security_audit",
        "tool": "audit_sql_injection",
        "source_hash": "abc",
        "result": {
            "findings": [
                {
                    "severity": "CRITICAL",
                    "issue": "triage confirmed, human dismissed",
                    "triage": {"verdict": "CONFIRMED", "reason": "model thinks real"},
                    "feedback": {"verdict": "FALSE_POSITIVE", "reason": "human knows better", "source": "human"},
                },
            ]
        },
    }
    report = _synthetic_report(entry)

    assert _highest_active_severity_at_or_above(report, "LOW") is False
