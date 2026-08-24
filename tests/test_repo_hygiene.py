"""Regressions for the outstanding-work sweep: things that were documented,
exported, or advertised but not actually wired."""

import inspect
import subprocess
import sys
from pathlib import Path

from agents.cli import AGENTS
from agents.luau_static import ROJO_RULE_IDS, analyze_repository

ROOT = Path(__file__).resolve().parents[1]


def test_every_exported_agent_is_registered_in_the_cli():
    import agents

    exported = {
        name
        for name in agents.__all__
        if name.endswith("Agent") or name == "DetectorTrainer"
    }
    registered = {cls.__name__ for cls in AGENTS.values()}
    # TriageAgent is the LLM second pass over a report, not a tool-handler
    # agent — it is driven by `scan --triage`, not `agents run`.
    missing = exported - registered - {"BaseAgent", "TriageAgent"}
    assert not missing, f"exported but unreachable from the CLI: {sorted(missing)}"
    assert "fleet_policy" in AGENTS


def test_readme_agent_and_tool_counts_match_the_code():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tools = sum(len(cls()._tool_handlers) for cls in AGENTS.values())
    words = {22: "Twenty-two", 23: "Twenty-three", 24: "Twenty-four"}
    assert f"{words[len(AGENTS)]} specialized agents ({tools} tools total)" in readme


MIRRORS = {
    "api_architect": "api-architect",
    "auth_security": "auth-security-reviewer",
    "code_review": "fullstack-code-reviewer",
    "compliance": "compliance-auditor",
    "config_audit": "config-auditor",
    "database_architect": "database-architect",
    "figma_scaffold": "figma-scaffolder",
    "fleet_policy": "fleet-policy-auditor",
    "flow_audit": "flow-auditor",
    "frontend_performance": "frontend-performance-reviewer",
    "healing": "healing-agent",
    "iac_security": "iac-security-reviewer",
    "infra_monitor": "infra-monitor",
    "mobile_deploy": "mobile-deploy-advisor",
    "postmortem": "postmortem-analyst",
    "railway_deploy": "railway-deploy-advisor",
    "roblox_audit": "roblox-auditor",
    "scaffolder": "project-scaffolder",
    "security_audit": "security-auditor",
    "stripe_billing": "stripe-billing-reviewer",
    "supply_chain_audit": "supply-chain-auditor",
    "training": "detector-trainer",
    "ui_generation": "ui-designer",
}


def test_every_python_agent_has_a_claude_code_mirror():
    """The v2.9 invariant: every agent in AGENTS is reachable as a Claude Code
    subagent. Adding an agent means adding a mirror and a row here."""
    assert set(MIRRORS) == set(AGENTS), f"unmapped: {set(AGENTS) ^ set(MIRRORS)}"
    for key, mirror in MIRRORS.items():
        path = ROOT / ".claude/agents" / f"{mirror}.md"
        assert path.is_file(), f"{key}: missing mirror {path.name}"
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\nname: " + mirror + "\n"), mirror
        assert "description:" in text and "tools:" in text, mirror


def test_tool_schema_properties_are_accepted_by_their_handlers():
    """A schema property the handler can't take makes the model's call fail
    with a swallowed TypeError — validate_accessibility used to advertise its
    outputs as inputs."""
    problems = []
    for name, cls in AGENTS.items():
        agent = cls()
        for tool in agent._tools:
            schema = tool.get("parameters") or tool.get("input_schema") or {}
            props = set((schema.get("properties") or {}).keys())
            handler = agent._tool_handlers.get(tool["name"])
            if handler is None:
                problems.append(f"{name}.{tool['name']}: no handler")
                continue
            params = inspect.signature(handler).parameters
            if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
                continue
            extra = props - set(params)
            if extra:
                problems.append(f"{name}.{tool['name']}: {sorted(extra)}")
    assert not problems, problems


def test_luau_rules_filter_accepts_the_ids_the_report_prints(tmp_path):
    (tmp_path / "Main.lua").write_text("local x = require(script.Parent.Missing)\n")
    (tmp_path / "default.project.json").write_text(
        '{"name": "t", "tree": {"$className": "DataModel", "ServerScriptService": {"$path": "nope"}}}'
    )
    baseline = analyze_repository(str(tmp_path))
    ids = {f["rule"] for f in baseline["findings"]}
    assert "unresolved_require" in ids
    assert ids & ROJO_RULE_IDS

    only_requires = analyze_repository(str(tmp_path), rules=["unresolved_require"])
    assert {f["rule"] for f in only_requires["findings"]} == {"unresolved_require"}

    only_rojo = analyze_repository(str(tmp_path), rules=["rojo_missing_path"])
    assert {f["rule"] for f in only_rojo["findings"]} <= ROJO_RULE_IDS
    assert only_rojo["findings"]


def test_drizzle_primary_key_check_is_per_table():
    from agents.code_review import CodeReviewAgent

    schema = (
        "export const users = pgTable('users', { id: serial('id').primaryKey() });\n"
        "export const posts = pgTable('posts', { title: text('title') });\n"
    )
    issues = [
        f["issue"] for f in CodeReviewAgent()._review_drizzle_schema(schema)["findings"]
    ]
    assert "Table `posts` has no primary key defined" in issues
    assert "Table `users` has no primary key defined" not in issues


def test_documented_public_wrappers_exist():
    from agents.healing import HealingAgent
    from agents.training import DetectorTrainer

    assert callable(HealingAgent.generate_patch)
    assert callable(HealingAgent.apply_patch_and_test)
    assert callable(DetectorTrainer.train)


def test_cli_help_lists_every_subcommand_the_readme_documents():
    out = subprocess.run(
        [sys.executable, "-m", "agents.cli", "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for cmd in (
        "serve",
        "prospect-report",
        "fix",
        "precision",
        "scaffold-app-from-figma",
    ):
        assert cmd in out, cmd


def test_example_script_runs_without_api_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = subprocess.run(
        [sys.executable, str(ROOT / "example.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
