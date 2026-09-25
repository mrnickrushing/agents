"""
Test Quality Agent — auditing the tests themselves.

A scanner that skips test files cannot tell you whether the tests it skipped
are worth anything. These checks read them: assertions that are not there,
waits that make a suite flaky, assertions that only prove a mock was called,
and tests switched off with no note saying why.

Deterministic and keyless::

    from agents import TestQualityAgent
    agent = TestQualityAgent()
    agent._audit_test_assertions(code=source)["findings"]
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

from agents.base import BaseAgent

# ── Locating tests ────────────────────────────────────────────────────────────

_PY_TEST_RE = re.compile(
    # `async def test_*` is an ordinary pytest test; missing it meant a suite of
    # only async tests was skipped entirely, even though the CLI glob picked the
    # file up and reported the agent as having reviewed it.
    r"^(?P<indent>[ \t]*)(?:async\s+)?def (?P<name>test_\w+)\s*\(",
    re.MULTILINE,
)
_JS_TEST_RE = re.compile(
    r"""^(?P<indent>[ \t]*)(?:it|test)\s*(?:\.\w+)?\s*\(\s*["'`](?P<name>[^"'`]+)""",
    re.MULTILINE,
)

#: Anything that can fail a test.
_ASSERTION_RE = re.compile(
    r"\bassert\b|\bself\.assert\w+\s*\(|\bpytest\.raises\b|\bassertRaises\b"
    r"|\bexpect\s*\(|\.should\b|\bassert\.\w+\s*\(|\bchai\b"
    r"|\bsnapshot\b|\bverify\s*\(|\bshouldBe\b|\bassertThat\s*\(",
    re.IGNORECASE,
)

#: A call of any kind — a test that exercises code but asserts nothing at least
#: proves it does not raise, which is weaker but not empty.
_CALL_RE = re.compile(r"\w\s*\(")


def _python_bodies(code: str) -> List[Tuple[str, int, str]]:
    """(name, line, body) for each Python test function."""
    found: List[Tuple[str, int, str]] = []
    matches = list(_PY_TEST_RE.finditer(code))
    for index, match in enumerate(matches):
        start = code.find("\n", match.end())
        end = matches[index + 1].start() if index + 1 < len(matches) else len(code)
        if start == -1:
            continue
        found.append(
            (
                match.group("name"),
                code[: match.start()].count("\n") + 1,
                code[start:end],
            )
        )
    return found


def _js_bodies(code: str) -> List[Tuple[str, int, str]]:
    """(name, line, body) for each JS/TS test block, bounded by the next one."""
    found: List[Tuple[str, int, str]] = []
    matches = list(_JS_TEST_RE.finditer(code))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(code)
        found.append(
            (
                match.group("name"),
                code[: match.start()].count("\n") + 1,
                code[match.end() : end],
            )
        )
    return found


def _test_bodies(code: str) -> List[Tuple[str, int, str]]:
    return _python_bodies(code) + _js_bodies(code)


def _looks_like_tests(code: str) -> bool:
    return bool(_PY_TEST_RE.search(code) or _JS_TEST_RE.search(code))


def _string_spans(code: str) -> List[Tuple[int, int]]:
    """Byte ranges covered by string literals.

    A meta-test — a test file that embeds test source as fixture data — holds
    `time.sleep(3)` inside a quoted string. Read as code, that is a flaky wait;
    read as data, it is the input to a test of this very checker. Reusing the
    literal walker from the security scanner keeps the two apart.
    """
    from agents.security_audit import _string_literals

    return [(begin, end) for _p, _q, _b, begin, end in _string_literals(code)]


def _outside_strings(spans: List[Tuple[int, int]], position: int) -> bool:
    return not any(begin <= position < end for begin, end in spans)


def _finding(severity: str, issue: str, fix: str, **extra: Any) -> Dict[str, Any]:
    finding = {"severity": severity, "issue": issue, "fix": fix}
    finding.update({key: value for key, value in extra.items() if value})
    return finding


# ── Assertions ────────────────────────────────────────────────────────────────


def _audit_test_assertions_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    empty: List[str] = []
    smoke: List[str] = []

    for name, line, body in _test_bodies(code):
        stripped = "\n".join(
            row
            for row in body.splitlines()
            if row.strip() and not row.strip().startswith("#")
        )
        if _ASSERTION_RE.search(stripped):
            continue
        # A body that only says `pass` tests nothing at all. One that calls
        # something at least proves it does not raise — weaker, not empty, so
        # the two are reported differently rather than lumped together.
        if _CALL_RE.search(stripped):
            smoke.append(f"{name}:{line}")
        else:
            empty.append(f"{name}:{line}")

    if empty:
        findings.append(
            _finding(
                "HIGH",
                f"{len(empty)} test(s) assert nothing and call nothing — they pass "
                "unconditionally and cannot fail",
                "Give each one an assertion, or delete it. A test that cannot fail is "
                "worse than no test: it reports coverage it does not provide.",
                evidence=", ".join(empty[:5]),
            )
        )
    if smoke:
        findings.append(
            _finding(
                "LOW",
                f"{len(smoke)} test(s) exercise code but assert nothing — they only "
                "prove the call does not raise",
                "Assert on the return value or the resulting state, so a wrong answer "
                "fails the test rather than passing quietly.",
                evidence=", ".join(smoke[:5]),
            )
        )
    return findings


# ── Flakiness ─────────────────────────────────────────────────────────────────

_SLEEP_RE = re.compile(
    r"\btime\.sleep\s*\(|\bsetTimeout\s*\(\s*\w+\s*,\s*\d{3,}"
    r"|\bawait\s+new\s+Promise\s*\([^)]*setTimeout|\bsleep\s*\(\s*\d"
)
_REAL_CLOCK_RE = re.compile(
    r"\b(?:datetime\.now|Date\.now|time\.time|new Date\s*\(\s*\))\s*\(?\)?"
)
#: A URL only counts when it is the argument of a request. Matching any URL in
#: the file reported a test that merely asserts `urls["Homepage"] == "https://..."`
#: as reaching that host, which is the opposite of what the check is for.
_REAL_NETWORK_RE = re.compile(
    r"""\b(?:requests\.\w+|httpx\.\w+|urlopen|urlretrieve|fetch|axios(?:\.\w+)?"""
    r"""|got|superagent\.\w+|session\.\w+)\s*\(\s*["'`]"""
    r"""(?P<url>https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(?:com|org))[\w.-]+)"""
)
_RANDOM_RE = re.compile(r"\brandom\.\w+\s*\(|\bMath\.random\s*\(|\buuid4\s*\(")


def _first_outside_strings(pattern: "re.Pattern[str]", code: str, spans):
    """First match of ``pattern`` that is real code rather than fixture data."""
    for match in pattern.finditer(code):
        if _outside_strings(spans, match.start()):
            return match
    return None


def _audit_test_flakiness_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not _looks_like_tests(code):
        return findings

    spans = _string_spans(code)
    sleep = _first_outside_strings(_SLEEP_RE, code, spans)
    if sleep:
        findings.append(
            _finding(
                "MEDIUM",
                "Test waits on a sleep rather than a condition — it fails on a slow "
                "machine and wastes time on a fast one",
                "Poll for the condition with a deadline, or await the signal the code "
                "under test actually emits.",
                line=code[: sleep.start()].count("\n") + 1,
                evidence=sleep.group(0),
            )
        )

    network = _first_outside_strings(_REAL_NETWORK_RE, code, spans)
    if network and not re.search(
        r"\bmock|\bnock\b|responses\.|httpretty|msw", code, re.IGNORECASE
    ):
        findings.append(
            _finding(
                "MEDIUM",
                f"Test reaches a real network host ({network.group('url')}) with no stub — "
                "it fails when that host is slow, down, or unreachable from CI",
                "Stub the request. A test that needs the internet is an integration "
                "test and belongs behind its own marker.",
                line=code[: network.start()].count("\n") + 1,
            )
        )

    clock = _first_outside_strings(_REAL_CLOCK_RE, code, spans)
    if clock and not re.search(
        r"freeze_time|freezegun|fakeTimers|useFakeTimers|monkeypatch", code
    ):
        findings.append(
            _finding(
                "LOW",
                "Test reads the real clock without freezing it — behaviour can depend "
                "on when it runs",
                "Freeze time (freezegun, jest fake timers) or inject the clock.",
                line=code[: clock.start()].count("\n") + 1,
            )
        )

    unseeded = _first_outside_strings(_RANDOM_RE, code, spans)
    if unseeded and not re.search(r"\bseed\s*\(", code):
        findings.append(
            _finding(
                "LOW",
                "Test uses randomness with no seed — a failure may not reproduce",
                "Seed the generator, or use fixed values so a failing run can be replayed.",
                line=code[: unseeded.start()].count("\n") + 1,
            )
        )

    return findings


# ── Mock-only assertions ──────────────────────────────────────────────────────

_MOCK_ASSERT_RE = re.compile(
    r"\bassert_(?:called|any_call|has_calls|not_called)\w*\s*\(|\.called\b"
    r"|toHaveBeenCalled\w*\s*\(|\btoHaveBeenNthCalledWith\b|\.mock\.calls\b",
    re.IGNORECASE,
)


def _audit_test_mocking_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    offenders: List[str] = []

    for name, line, body in _test_bodies(code):
        if not _MOCK_ASSERT_RE.search(body):
            continue
        # Strip the mock assertions and see whether anything is left that
        # checks a real value. A test asserting both is doing its job.
        remainder = _MOCK_ASSERT_RE.sub("", body)
        if not _ASSERTION_RE.search(remainder):
            offenders.append(f"{name}:{line}")

    if offenders:
        findings.append(
            _finding(
                "MEDIUM",
                f"{len(offenders)} test(s) only assert that a mock was called — they "
                "verify the test's own wiring, not the behaviour",
                "Assert on what the code returns or changes. A mock-call assertion "
                "passes even when the real implementation is wrong, and breaks on a "
                "refactor that keeps behaviour identical.",
                evidence=", ".join(offenders[:5]),
            )
        )
    return findings


# ── Disabled tests ────────────────────────────────────────────────────────────

_SKIP_RE = re.compile(
    r"@(?:pytest\.mark\.)?(?:skip|xfail)\b(?P<py_args>[^\n]*)"
    r"|@unittest\.skip\w*\b(?P<ut_args>[^\n]*)"
    r"|\b(?:it|test|describe)\.(?:skip|todo)\s*\(|\bxit\s*\(|\bxdescribe\s*\("
)


def _audit_skipped_tests_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    unexplained: List[str] = []
    total = 0

    spans = _string_spans(code)
    for match in _SKIP_RE.finditer(code):
        if not _outside_strings(spans, match.start()):
            continue
        total += 1
        args = (match.group("py_args") or "") + (match.group("ut_args") or "")
        # A reason is what turns a skip from a mystery into a decision.
        if not re.search(r"reason\s*=|['\"][^'\"]{8,}", args):
            unexplained.append(f"line {code[: match.start()].count(chr(10)) + 1}")

    if unexplained:
        findings.append(
            _finding(
                "MEDIUM",
                f"{len(unexplained)} of {total} disabled test(s) give no reason — "
                "nobody can tell whether they are still worth fixing",
                'Add reason="..." naming what must change before it is re-enabled, '
                "or delete the test.",
                evidence=", ".join(unexplained[:5]),
            )
        )
    return findings


# ── Agent ─────────────────────────────────────────────────────────────────────


class TestQualityAgent(BaseAgent):
    """Audits test suites for tests that cannot fail, flake, or prove nothing."""

    #: pytest collects any class named Test*, and would warn about this one on
    #: every run of a suite that imports it. It is an agent, not a test case.
    __test__ = False

    name = "test_quality"
    description = (
        "Audits the tests themselves — assertion-free tests that cannot fail, "
        "sleep/clock/network/randomness flakiness, assertions that only prove a "
        "mock was called, and tests disabled with no reason."
    )
    model = "gpt-5"

    system_prompt = """\
You review test suites, holding them to the standard the code is held to.

What you look for, in order of how much it costs the team:

- A test that cannot fail. Assertion-free and call-free bodies report coverage \
they do not provide, which is worse than an honest gap.
- A test that fails for reasons unrelated to the code: a sleep instead of a \
condition, a real network host, the real clock, unseeded randomness. Every \
one of these teaches people to re-run rather than read.
- A test that asserts only that a mock was called. It passes when the real \
implementation is wrong and fails on a refactor that changed nothing.
- A test switched off with no reason recorded, so nobody can tell whether it \
is worth fixing.

Name the test and say what would have to break for it to fail. If the answer \
is "nothing", that is the finding.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        code_param = {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        }
        return [
            {
                "name": "audit_test_assertions",
                "description": "Detects tests that assert nothing — unconditional passes and bare smoke tests.",
                "parameters": code_param,
            },
            {
                "name": "audit_test_flakiness",
                "description": "Detects sleep-based waits, real network calls, real clock reads, and unseeded randomness in tests.",
                "parameters": code_param,
            },
            {
                "name": "audit_test_mocking",
                "description": "Detects tests whose only assertions are that a mock was called.",
                "parameters": code_param,
            },
            {
                "name": "audit_skipped_tests",
                "description": "Detects skipped or xfailed tests with no recorded reason.",
                "parameters": code_param,
            },
            {
                "name": "audit_test_suite",
                "description": (
                    "Run every test-quality check over one test file. This is what "
                    "the project scan calls; the individual tools above are for "
                    "looking at one dimension at a time."
                ),
                "parameters": code_param,
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "audit_test_assertions": self._audit_test_assertions,
            "audit_test_flakiness": self._audit_test_flakiness,
            "audit_test_mocking": self._audit_test_mocking,
            "audit_skipped_tests": self._audit_skipped_tests,
            "audit_test_suite": self._audit_test_suite,
        }

    def _audit_test_assertions(self, code: str) -> Dict[str, Any]:
        findings = _audit_test_assertions_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_test_flakiness(self, code: str) -> Dict[str, Any]:
        findings = _audit_test_flakiness_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_test_mocking(self, code: str) -> Dict[str, Any]:
        findings = _audit_test_mocking_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_skipped_tests(self, code: str) -> Dict[str, Any]:
        findings = _audit_skipped_tests_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_test_suite(self, code: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for check in (
            _audit_test_assertions_impl,
            _audit_test_flakiness_impl,
            _audit_test_mocking_impl,
            _audit_skipped_tests_impl,
        ):
            findings.extend(check(code))
        return {"findings": findings, "total_issues": len(findings)}


__all__ = ["TestQualityAgent"]
