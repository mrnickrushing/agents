import json

from agents.evolution import EvolutionStore, attach_finding_ids


def _report(project, issue="Missing authentication"):
    return {
        "project": str(project),
        "files_scanned": 1,
        "files_matched": 1,
        "summary": {"HIGH": 1},
        "coverage": {},
        "results": [
            {
                "file": "route.py",
                "agent": "auth_security",
                "tool": "audit_shared_secret_auth",
                "result": {
                    "findings": [
                        {
                            "severity": "HIGH",
                            "issue": issue,
                            "fix": "Require authentication.",
                        }
                    ]
                },
            }
        ],
    }


def _finding(report):
    return report["results"][0]["result"]["findings"][0]


def test_finding_id_is_stable_until_source_changes(tmp_path):
    source = tmp_path / "route.py"
    source.write_text("def route(): return True\n")

    first = _report(tmp_path)
    second = _report(tmp_path)
    attach_finding_ids(first)
    attach_finding_ids(second)

    assert _finding(first)["finding_id"] == _finding(second)["finding_id"]

    source.write_text("def route(): return False\n")
    changed = _report(tmp_path)
    attach_finding_ids(changed)

    assert _finding(changed)["finding_id"] != _finding(first)["finding_id"]


def test_human_feedback_is_applied_to_an_unchanged_finding(tmp_path):
    (tmp_path / "route.py").write_text("def route(): return True\n")
    database = tmp_path / "evolution.db"
    first = _report(tmp_path)

    with EvolutionStore(str(database)) as store:
        store.apply_feedback(first)
        scan_id = store.record_scan(first, detector_version="test")
        finding_id = _finding(first)["finding_id"]
        store.add_feedback(
            finding_id, "dismiss", "Authentication is enforced by middleware."
        )

        next_report = _report(tmp_path)
        store.apply_feedback(next_report)

    assert scan_id.startswith("ags_")
    assert _finding(next_report)["feedback"] == {
        "verdict": "FALSE_POSITIVE",
        "reason": "Authentication is enforced by middleware.",
        "source": "human",
        "created_at": _finding(next_report)["feedback"]["created_at"],
    }
    assert next_report["results"][0]["feedback"]["verdict"] == "FALSE_POSITIVE"
    assert next_report["evolution"]["learned_verdicts_applied"] == 1


def test_human_feedback_outranks_triage_and_eval_measures_agreement(tmp_path):
    (tmp_path / "route.py").write_text("def route(): return True\n")
    report = _report(tmp_path)
    _finding(report)["triage"] = {
        "verdict": "CONFIRMED",
        "reason": "The model believes the route is exposed.",
    }

    with EvolutionStore(str(tmp_path / "evolution.db")) as store:
        store.record_scan(report, detector_version="test")
        finding_id = _finding(report)["finding_id"]
        store.add_feedback(finding_id, "dismiss", "Middleware covers this route.")

        repeated = _report(tmp_path)
        store.apply_feedback(repeated)
        evaluation = store.evaluate(project=str(tmp_path))

    assert _finding(repeated)["feedback"]["source"] == "human"
    assert _finding(repeated)["feedback"]["verdict"] == "FALSE_POSITIVE"
    assert evaluation["labeled_findings"] == 1
    assert evaluation["confirmed"] == 0
    assert evaluation["false_positive"] == 1
    assert evaluation["actionable_precision"] == 0.0
    assert evaluation["triage_comparisons"] == 1
    assert evaluation["triage_agreement"] == 0.0
    assert evaluation["recall"] is None


def test_history_can_be_scoped_to_a_project(tmp_path):
    first_project = tmp_path / "first"
    second_project = tmp_path / "second"
    first_project.mkdir()
    second_project.mkdir()
    (first_project / "route.py").write_text("first")
    (second_project / "route.py").write_text("second")

    with EvolutionStore(str(tmp_path / "evolution.db")) as store:
        store.record_scan(_report(first_project), detector_version="one")
        store.record_scan(_report(second_project), detector_version="two")

        all_runs = store.recent_runs()
        first_runs = store.recent_runs(project=str(first_project))

    assert len(all_runs) == 2
    assert len(first_runs) == 1
    assert first_runs[0]["project_path"] == str(first_project)


def test_recorded_report_is_valid_json(tmp_path):
    (tmp_path / "route.py").write_text("route")
    with EvolutionStore(str(tmp_path / "evolution.db")) as store:
        scan_id = store.record_scan(_report(tmp_path), detector_version="test")
        row = store.connection.execute(
            "SELECT report_json FROM scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone()

    stored = json.loads(row["report_json"])
    assert stored["scan_id"] == scan_id
    assert _finding(stored)["finding_id"].startswith("agf_")
