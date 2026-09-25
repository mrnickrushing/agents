"""Tests for the llm_security, test_quality, and docs_drift agents."""

import pytest

from agents.docs_drift import DocsDriftAgent
from agents.llm_security import LLMSecurityAgent
from agents.test_quality import TestQualityAgent

# ── llm_security ──────────────────────────────────────────────────────────────


@pytest.fixture
def llm():
    return LLMSecurityAgent()


def _sev(findings):
    return [f["severity"] for f in findings]


@pytest.mark.parametrize(
    "code",
    [
        # JSON-style quoted key — the common spelling, and the one a regex
        # requiring `role` against the colon silently misses.
        """import openai\nmessages = [{"role": "system", "content": f"Bot. Ctx: {req.body.c}"}]""",
        # Keyword argument form.
        """import anthropic\nclient.messages.create(system=f"Bot: {user_input}", max_tokens=5)""",
        # JS object with a template literal.
        """import OpenAI from "openai";\n"""
        """const m = [{ role: "system", content: `Bot ${req.body.ctx}` }];""",
    ],
)
def test_untrusted_input_in_system_prompt_is_critical(llm, code):
    findings = llm._audit_prompt_construction(code=code)["findings"]
    assert _sev(findings) == ["CRITICAL"]


@pytest.mark.parametrize(
    "code",
    [
        # The correct shape: constant instructions, user text in its own turn.
        """import openai\nmessages = [\n  {"role": "system", "content": "You are helpful."},\n"""
        """  {"role": "user", "content": req.body.message},\n]""",
        # Interpolated, but from a trusted value.
        """import openai\nmessages = [{"role": "system", "content": f"Today is {today}."}]""",
        # No model anywhere — not this agent's business.
        """config = {"role": "system", "content": f"{req.body.x}"}""",
    ],
)
def test_correct_prompt_construction_is_silent(llm, code):
    assert llm._audit_prompt_construction(code=code)["findings"] == []


def test_user_message_after_a_static_system_message_is_not_blamed_on_it(llm):
    """The window must stop at the next role, or the user turn that correctly
    carries untrusted input gets read as part of the system message."""
    code = (
        "import openai\n"
        "messages = [\n"
        '  {"role": "system", "content": "You are helpful."},\n'
        '  {"role": "user", "content": f"{req.body.message}"},\n'
        "]"
    )
    assert llm._audit_prompt_construction(code=code)["findings"] == []


def test_uncapped_token_spend_is_reported(llm):
    findings = llm._audit_token_limits(
        code='client.chat.completions.create(model="gpt-4", messages=m)'
    )["findings"]
    assert any("token cap" in f["issue"] for f in findings)


def test_capped_call_with_timeout_is_silent(llm):
    code = 'client.chat.completions.create(model="gpt-4", messages=m, max_tokens=100, timeout=30)'
    assert llm._audit_token_limits(code=code)["findings"] == []


def test_model_call_in_unbounded_loop_is_high(llm):
    code = (
        "import openai\n"
        "while True:\n"
        "    openai.chat.completions.create(model='x', messages=m, max_tokens=5, timeout=2)\n"
    )
    findings = llm._audit_token_limits(code=code)["findings"]
    assert "HIGH" in _sev(findings)


def test_loop_with_a_break_is_not_flagged_as_unbounded(llm):
    code = (
        "import openai\n"
        "while True:\n"
        "    r = openai.chat.completions.create(model='x', messages=m, max_tokens=5, timeout=2)\n"
        "    if r.done:\n        break\n"
    )
    findings = llm._audit_token_limits(code=code)["findings"]
    assert "HIGH" not in _sev(findings)


@pytest.mark.parametrize(
    "code",
    [
        "const c = new OpenAI({dangerouslyAllowBrowser: true});",
        "const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;",
        "const key = process.env.VITE_ANTHROPIC_API_KEY;",
        'client = OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz")',
    ],
)
def test_keys_reaching_the_client_are_critical(llm, code):
    findings = llm._audit_llm_key_exposure(code=code)["findings"]
    assert findings and set(_sev(findings)) == {"CRITICAL"}


def test_server_side_key_is_silent(llm):
    assert (
        llm._audit_llm_key_exposure(code="key = os.getenv('OPENAI_API_KEY')")[
            "findings"
        ]
        == []
    )


def test_model_output_into_innerhtml_is_reported(llm):
    code = (
        'const reply = await openai.chat.completions.create({model:"x", messages});\n'
        "el.innerHTML = reply.choices[0].message.content;\n"
    )
    findings = llm._audit_llm_output_handling(code=code)["findings"]
    assert _sev(findings) == ["CRITICAL"]


def test_unrelated_sink_is_not_blamed_on_the_model(llm):
    """An eval elsewhere in the file must not be attributed to model output."""
    code = (
        'const reply = await openai.chat.completions.create({model:"x", messages});\n'
        "const parsed = eval(staticConfigString);\n"
        "render(reply.choices[0].message.content);\n"
    )
    assert llm._audit_llm_output_handling(code=code)["findings"] == []


def test_tool_reaching_a_shell_is_reported(llm):
    code = (
        "import anthropic\n"
        'tools = [{"type": "function", "name": "run"}]\n'
        "def run(cmd):\n    subprocess.run(cmd, shell=True)\n"
    )
    findings = llm._audit_llm_tool_exposure(code=code)["findings"]
    assert _sev(findings) == ["HIGH"]


def test_validated_tool_is_downgraded_not_silenced(llm):
    code = (
        "import anthropic\n"
        'tools = [{"type": "function", "name": "run"}]\n'
        "def run(cmd):\n    validate_command(cmd)\n    subprocess.run(shlex.quote(cmd))\n"
    )
    findings = llm._audit_llm_tool_exposure(code=code)["findings"]
    assert _sev(findings) == ["MEDIUM"]


def test_file_with_no_model_call_is_untouched(llm):
    code = "def add(a, b):\n    return a + b\n"
    for handler in llm._tool_handlers.values():
        assert handler(code=code)["findings"] == []


# ── test_quality ──────────────────────────────────────────────────────────────


@pytest.fixture
def tq():
    return TestQualityAgent()


def test_empty_test_is_high(tq):
    findings = tq._audit_test_assertions(code="def test_nothing():\n    pass\n")[
        "findings"
    ]
    assert _sev(findings) == ["HIGH"]
    assert "cannot fail" in findings[0]["issue"]


def test_smoke_test_is_low_not_high(tq):
    """Calling code to prove it does not raise is weak, not worthless — the two
    are reported differently rather than lumped together."""
    findings = tq._audit_test_assertions(code="def test_smoke():\n    build_thing()\n")[
        "findings"
    ]
    assert _sev(findings) == ["LOW"]


def test_real_assertions_are_silent(tq):
    assert (
        tq._audit_test_assertions(code="def test_x():\n    assert add(1, 2) == 3\n")[
            "findings"
        ]
        == []
    )


@pytest.mark.parametrize(
    "assertion",
    [
        "assert x == 1",
        "self.assertEqual(x, 1)",
        "expect(x).toBe(1)",
        "with pytest.raises(ValueError):\n        boom()",
    ],
)
def test_every_assertion_dialect_counts(tq, assertion):
    code = f"def test_x():\n    {assertion}\n"
    assert tq._audit_test_assertions(code=code)["findings"] == []


def test_sleep_based_wait_is_flagged(tq):
    code = "import time\ndef test_x():\n    time.sleep(3)\n    assert done\n"
    findings = tq._audit_test_flakiness(code=code)["findings"]
    assert any("sleep" in f["issue"] for f in findings)


def test_real_network_host_is_flagged(tq):
    code = 'def test_x():\n    r = requests.get("https://api.stripe.com/v1/charges")\n    assert r.ok\n'
    findings = tq._audit_test_flakiness(code=code)["findings"]
    assert any("network" in f["issue"] for f in findings)


def test_stubbed_network_is_silent(tq):
    code = (
        "def test_x(responses):\n"
        '    responses.add("https://api.stripe.com/v1/charges")\n'
        "    assert call().ok\n"
    )
    findings = tq._audit_test_flakiness(code=code)["findings"]
    assert not any("network" in f["issue"] for f in findings)


def test_frozen_clock_is_silent(tq):
    code = "@freeze_time('2026-01-01')\ndef test_x():\n    assert datetime.now().year == 2026\n"
    findings = tq._audit_test_flakiness(code=code)["findings"]
    assert not any("clock" in f["issue"] for f in findings)


def test_mock_only_assertion_is_flagged(tq):
    code = "def test_x(mock_send):\n    run()\n    mock_send.assert_called_once()\n"
    findings = tq._audit_test_mocking(code=code)["findings"]
    assert _sev(findings) == ["MEDIUM"]


def test_mock_plus_real_assertion_is_silent(tq):
    code = "def test_x(mock_send):\n    out = run()\n    mock_send.assert_called_once()\n    assert out == 5\n"
    assert tq._audit_test_mocking(code=code)["findings"] == []


def test_skip_without_reason_is_flagged(tq):
    findings = tq._audit_skipped_tests(
        code="@pytest.mark.skip\ndef test_x():\n    assert 1\n"
    )["findings"]
    assert _sev(findings) == ["MEDIUM"]


def test_skip_with_reason_is_silent(tq):
    code = '@pytest.mark.skip(reason="blocked on upstream fix #42")\ndef test_x():\n    assert 1\n'
    assert tq._audit_skipped_tests(code=code)["findings"] == []


def test_non_test_file_is_untouched(tq):
    code = "def helper():\n    pass\n"
    for handler in tq._tool_handlers.values():
        assert handler(code=code)["findings"] == []


def test_suite_tool_aggregates_every_check(tq):
    code = (
        "import time\n"
        "def test_empty():\n    pass\n"
        "def test_slow():\n    time.sleep(2)\n    assert 1\n"
        "@pytest.mark.skip\ndef test_off():\n    assert 1\n"
    )
    aggregate = tq._audit_test_suite(code=code)["findings"]
    individual = sum(
        len(tq._tool_handlers[name](code=code)["findings"])
        for name in (
            "audit_test_assertions",
            "audit_test_flakiness",
            "audit_test_mocking",
            "audit_skipped_tests",
        )
    )
    assert len(aggregate) == individual > 0


# ── docs_drift ────────────────────────────────────────────────────────────────


@pytest.fixture
def docs():
    return DocsDriftAgent()


def _drift(agent, files):
    return agent._audit_docs_drift(files=files)["findings"]


BASE_FILES = {
    "pyproject.toml": '[project.scripts]\nagents = "agents.cli:main"\n',
    "agents/cli.py": 'sub.add_parser("scan")\nsub.add_parser("review")\n',
}


def test_documented_command_that_does_not_exist_is_high(docs):
    files = dict(BASE_FILES)
    files["README.md"] = "```fish\nagents scan --path .\nagents bogus\n```\n"
    findings = [f for f in _drift(docs, files) if "command" in f["issue"]]
    assert _sev(findings) == ["HIGH"]
    assert "bogus" in findings[0]["evidence"]


def test_documented_commands_that_all_exist_are_silent(docs):
    files = dict(BASE_FILES)
    files["README.md"] = (
        "```fish\nagents scan --path .\nagents review --base main\n```\n"
    )
    assert [f for f in _drift(docs, files) if "command" in f["issue"]] == []


def test_prose_outside_a_fence_is_not_read_as_a_command(docs):
    files = dict(BASE_FILES)
    files["README.md"] = "The agents framework helps you ship faster.\n"
    assert [f for f in _drift(docs, files) if "command" in f["issue"]] == []


def test_env_var_read_but_undocumented_is_reported(docs):
    files = {
        ".env.example": "OPENAI_API_KEY=\n",
        "app.py": 'import os\nos.getenv("OPENAI_API_KEY")\nos.getenv("STRIPE_SECRET")\n',
    }
    findings = [
        f for f in _drift(docs, files) if "absent from the example" in f["issue"]
    ]
    assert _sev(findings) == ["MEDIUM"]
    assert "STRIPE_SECRET" in findings[0]["evidence"]


def test_env_var_documented_but_unread_is_low(docs):
    files = {
        ".env.example": "OPENAI_API_KEY=\nLEFTOVER=\n",
        "app.py": 'import os\nos.getenv("OPENAI_API_KEY")\n',
    }
    findings = [f for f in _drift(docs, files) if "read nowhere" in f["issue"]]
    assert _sev(findings) == ["LOW"]
    assert "LEFTOVER" in findings[0]["evidence"]


def test_platform_variables_are_not_reported_as_undocumented(docs):
    """NODE_ENV and PORT come from the platform, not a .env file."""
    files = {
        ".env.example": "OPENAI_API_KEY=\n",
        "app.js": "process.env.NODE_ENV; process.env.PORT; process.env.OPENAI_API_KEY;",
    }
    assert [
        f for f in _drift(docs, files) if "absent from the example" in f["issue"]
    ] == []


def test_broken_documentation_link_is_reported(docs):
    files = {
        "README.md": "See [deploy](docs/deploy.md) and [gone](docs/missing.md)\n",
        "docs/deploy.md": "# Deploy\n",
    }
    findings = [f for f in _drift(docs, files) if "link" in f["issue"]]
    assert _sev(findings) == ["MEDIUM"]
    assert "missing.md" in findings[0]["evidence"]


@pytest.mark.parametrize(
    "link",
    [
        "https://example.com/x.md",
        "#a-heading",
        "mailto:a@b.com",
        "logo.png",
        "diagram.svg",
    ],
)
def test_external_anchor_and_binary_links_are_not_checked(docs, link):
    """A binary is never in a text scan's file map, so calling it missing would
    be an artefact of what was collected rather than a real broken link."""
    files = {"README.md": f"[x]({link})\n"}
    assert [f for f in _drift(docs, files) if "link" in f["issue"]] == []


def test_relative_links_resolve_against_the_documents_own_directory(docs):
    files = {
        "docs/guide.md": "See [deploy](./deploy.md)\n",
        "docs/deploy.md": "# Deploy\n",
    }
    assert [f for f in _drift(docs, files) if "link" in f["issue"]] == []


def test_a_one_sided_view_produces_silence(docs):
    """The rule that keeps this usable: with only one side visible, say nothing."""
    assert _drift(docs, {"agents/cli.py": 'sub.add_parser("scan")'}) == []
    assert _drift(docs, {"app.py": 'os.getenv("ANYTHING")'}) == []
    assert _drift(docs, {}) == []


def test_agent_is_registered_and_mirrored():
    from agents.cli import AGENTS

    for key in ("llm_security", "test_quality", "docs_drift"):
        assert key in AGENTS
        agent = AGENTS[key]()
        assert set(agent._tool_handlers) == {t["name"] for t in agent._define_tools()}


# ── Review fixes (PR #74, Codex) ──────────────────────────────────────────────


def test_static_system_prompt_beside_an_unrelated_log_is_not_injection(llm):
    """A fixed 400-character window ran past the end of the system message into
    the next statement, so a nearby log line interpolating request data was
    reported as CRITICAL prompt injection."""
    code = (
        "import openai\n"
        'messages = [{"role": "system", "content": "You are a helpful assistant."}]\n'
        'logger.info(f"Received {req.body.message}")\n'
    )
    assert llm._audit_prompt_construction(code=code)["findings"] == []


def test_anthropic_call_without_max_tokens_is_not_a_spend_finding(llm):
    """`messages.create` is rejected by the API before it generates or bills,
    so an absent cap there is an error, not a denial-of-wallet risk."""
    findings = llm._audit_token_limits(
        code='client.messages.create(model="x", messages=m, timeout=5)'
    )["findings"]
    assert not any("token cap" in f["issue"] for f in findings)


def test_openai_call_without_max_tokens_is_still_reported(llm):
    findings = llm._audit_token_limits(
        code='client.chat.completions.create(model="x", messages=m, timeout=5)'
    )["findings"]
    assert any("token cap" in f["issue"] for f in findings)


def test_an_unrelated_timeout_variable_does_not_cover_untimed_calls(llm):
    """A file-wide search for `timeout` let genuinely unbounded calls pass."""
    code = (
        "import openai\n"
        "timeout = 30\n"
        'openai.chat.completions.create(model="a", messages=m, max_tokens=5)\n'
    )
    findings = llm._audit_token_limits(code=code)["findings"]
    assert any("timeout" in f["issue"] for f in findings)


def test_client_level_timeout_covers_its_calls(llm):
    code = (
        "client = OpenAI(timeout=20)\n"
        'client.chat.completions.create(model="a", messages=m, max_tokens=5)\n'
    )
    assert llm._audit_token_limits(code=code)["findings"] == []


@pytest.mark.parametrize(
    "body,expected",
    [("    pass\n", 1), ("    assert await f() == 1\n", 0)],
)
def test_async_test_functions_are_recognised(tq, body, expected):
    """`async def test_*` was invisible, so a suite of only async tests was
    skipped even though the CLI glob selected the file."""
    findings = tq._audit_test_suite(code=f"async def test_x():\n{body}")["findings"]
    assert len(findings) == expected


def test_links_into_dot_directories_resolve(docs):
    """`lstrip("./")` strips a character set, so `.github/...` lost its dot and
    an existing file was reported missing."""
    files = {
        "README.md": "[CI](.github/workflows/ci.yml)\n",
        ".github/workflows/ci.yml": "name: CI\n",
    }
    assert [f for f in _drift(docs, files) if "link" in f["issue"]] == []


def test_repo_flag_builds_the_files_map_for_repository_wide_tools(tmp_path):
    """`--arg` coerces scalars only, so the repository-wide tools had no
    working CLI invocation at all."""
    from agents.cli import _collect_repo_files

    (tmp_path / "README.md").write_text("# Hi\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    collected = _collect_repo_files(str(tmp_path))
    assert collected["README.md"] == "# Hi\n"
    assert collected["app.py"] == "x = 1\n"


def test_run_parser_accepts_repo():
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "agents.cli", "run", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--repo" in completed.stdout
