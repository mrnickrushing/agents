"""Fingerprint + incident-memory tests.

The log samples here are real: they're trimmed from actual GitHub Actions
failures across these repos, which is the only honest way to check that a
signature survives the noise that genuinely varies between runs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agents.evolution import EvolutionStore
from agents.incidents import fingerprint, normalize_line, salient_lines

# Same failure, two different runs: different timestamps, runner paths, commit
# hashes, and durations. A signature that doesn't survive this is useless.
PYTEST_PATH_A = """
2026-08-23T02:07:24.1553710Z ##[group]Run pytest
2026-08-23T02:07:25.0000000Z /home/runner/work/aegisapparel/aegisapparel/backend
2026-08-23T02:07:26.1234567Z ImportError: cannot import name 'app' from 'server'
2026-08-23T02:07:26.2000000Z ##[error]Process completed with exit code 1.
"""
PYTEST_PATH_B = """
2026-07-11T19:44:02.9990001Z ##[group]Run pytest
2026-07-11T19:44:03.5000000Z /home/runner/work/Vitality/Vitality/backend
2026-07-11T19:44:05.7654321Z ImportError: cannot import name 'app' from 'server'
2026-07-11T19:44:05.9000000Z ##[error]Process completed with exit code 1.
"""

ESLINT_PEER = """
2026-08-23T01:43:58.0305296Z npm error code ELSPROBLEMS
2026-08-23T01:43:58.0305681Z npm error invalid: eslint@10.6.0 /home/runner/work/Vitality/Vitality/node_modules/eslint
2026-08-23T01:43:58.0326760Z ##[error]"npm ls" failed
"""

BILLING = """
2026-08-23T20:21:18Z The job was not started because recent account payments have failed
or your spending limit needs to be increased. Please check the 'Billing & plans' section
"""


def test_same_failure_different_runs_matches():
    sig_a, lines_a = fingerprint(PYTEST_PATH_A)
    sig_b, lines_b = fingerprint(PYTEST_PATH_B)
    assert sig_a == sig_b, f"\nA: {lines_a}\nB: {lines_b}"


def test_different_failures_do_not_collide():
    assert fingerprint(PYTEST_PATH_A)[0] != fingerprint(ESLINT_PEER)[0]
    assert fingerprint(ESLINT_PEER)[0] != fingerprint(BILLING)[0]


def test_normalization_scrubs_the_things_that_vary():
    norm = normalize_line(
        "2026-08-23T02:07:26.1234567Z ##[error]failed at /home/runner/work/x/y.ts:42 "
        "commit a17c003abcdef1234 version 1.2.3"
    )
    assert "2026-08-23" not in norm
    assert "##[error]" not in norm
    assert "/home/runner" not in norm
    assert "a17c003abcdef1234" not in norm
    assert "1.2.3" not in norm
    assert "failed" in norm


def test_salient_lines_skips_non_error_noise():
    log = "Installing dependencies\nadded 1079 packages\nERROR: build failed spectacularly"
    lines = salient_lines(log)
    assert len(lines) == 1
    assert "build failed" in lines[0]


def test_signature_is_bounded_by_line_count():
    # Forty stack frames and thirty should be the same failure.
    short = "\n".join(f"Error: frame {i} at /a/b/c.py" for i in range(30))
    long = "\n".join(f"Error: frame {i} at /a/b/c.py" for i in range(40))
    assert fingerprint(short)[0] == fingerprint(long)[0]


def test_log_with_no_error_lines_still_returns_a_signature():
    sig, lines = fingerprint("everything is completely fine\nall good here")
    assert sig and lines == []


def test_placeholder_only_lines_are_not_salient():
    # "error: 1" normalizes to "error: <n>" — too generic to key on.
    assert salient_lines("error: 1") == []


@pytest.fixture
def store():
    d = Path(tempfile.mkdtemp())
    s = EvolutionStore(str(d / "evolution.db"))
    yield s
    s.close()


def test_record_then_match_across_projects(store):
    store.record_incident(
        log=PYTEST_PATH_A,
        project_key="aegisapparel",
        surface="ci",
        check_name="Backend / Tests",
        summary="pytest cannot import the app module",
        root_cause="bare `pytest` does not add cwd to sys.path the way `python -m pytest` does",
        fix="add `pythonpath = .` under [tool:pytest] in setup.cfg",
        fix_ref="https://github.com/mrnickrushing/aegisapparel/pull/127",
    )
    # The same failure surfacing in a *different* repo is the whole point.
    result = store.match_incidents(PYTEST_PATH_B)
    assert len(result["incidents"]) == 1
    hit = result["incidents"][0]
    assert hit["project_key"] == "aegisapparel"
    assert "pythonpath" in hit["fix"]
    assert result["matched_on"]


def test_unrelated_failure_does_not_match(store):
    store.record_incident(
        log=PYTEST_PATH_A,
        project_key="aegisapparel",
        surface="ci",
        summary="s",
        root_cause="r",
        fix="f",
    )
    assert store.match_incidents(ESLINT_PEER)["incidents"] == []


def test_exclude_project_filters_own_history(store):
    store.record_incident(
        log=PYTEST_PATH_A,
        project_key="aegisapparel",
        surface="ci",
        summary="s",
        root_cause="r",
        fix="f",
    )
    assert (
        store.match_incidents(PYTEST_PATH_A, exclude_project="aegisapparel")[
            "incidents"
        ]
        == []
    )
    assert store.match_incidents(PYTEST_PATH_A, exclude_project="vitality")["incidents"]


def test_matches_are_newest_first(store):
    for i, proj in enumerate(["a", "b", "c"]):
        store.record_incident(
            log=PYTEST_PATH_A,
            project_key=proj,
            surface="ci",
            summary=f"s{i}",
            root_cause="r",
            fix="f",
        )
    projects = [
        i["project_key"] for i in store.match_incidents(PYTEST_PATH_A)["incidents"]
    ]
    assert projects[0] == "c"


def test_recent_incidents_can_filter_by_project(store):
    store.record_incident(
        log=PYTEST_PATH_A,
        project_key="a",
        surface="ci",
        summary="s",
        root_cause="r",
        fix="f",
    )
    store.record_incident(
        log=ESLINT_PEER,
        project_key="b",
        surface="ci",
        summary="s",
        root_cause="r",
        fix="f",
    )
    assert len(store.recent_incidents()) == 2
    assert len(store.recent_incidents(project="a")) == 1


def test_invalid_surface_is_rejected(store):
    with pytest.raises(ValueError):
        store.record_incident(
            log="x",
            project_key="a",
            surface="nonsense",
            summary="s",
            root_cause="r",
            fix="f",
        )


def test_raw_log_is_not_persisted(store):
    # Logs routinely contain tokens. Only the signature is needed to match.
    secret = "ghp_totallyrealtokenvalue1234567890"
    store.record_incident(
        log=f"Error: auth failed with {secret} at /a/b/c",
        project_key="a",
        surface="ci",
        summary="s",
        root_cause="r",
        fix="f",
    )
    dumped = "\n".join(store.connection.iterdump())
    assert secret not in dumped
