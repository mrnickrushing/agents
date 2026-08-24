import json
import subprocess

from agents.api_architect import APIArchitectAgent
from agents.cli import (
    AGENTS,
    RULES,
    _project_runtime_commands,
    _run_runtime_verification,
)
from agents.database_architect import DatabaseArchitectAgent
from agents.security_audit import SecurityAuditAgent


def test_new_agents_are_registered():
    assert {
        "flow_audit",
        "frontend_performance",
        "iac_security",
        "supply_chain_audit",
    } <= set(AGENTS)


def test_config_audit_new_surfaces_are_wired():
    globs = {
        (glob, tool) for glob, _, agent, tool, _ in RULES if agent == "config_audit"
    }
    assert ("next.config.js", "audit_framework_config") in globs
    assert ("tsconfig.json", "audit_tsconfig") in globs
    assert ("build.gradle", "audit_gradle_config") in globs
    assert (".env.local", "audit_env_local") in globs
    assert ("nginx.conf", "audit_webserver_config") in globs


def test_security_dependency_scan_supports_lockfiles():
    agent = SecurityAuditAgent()
    cargo = """
version = 3

[[package]]
name = "openssl"
version = "0.10.57"
"""
    result = agent._scan_dependencies(cargo)
    assert result["ecosystem"] == "rust"
    assert result["dependencies_count"] >= 1


def test_secret_audit_detects_url_embedded_secret():
    agent = SecurityAuditAgent()
    code = "const upstream = 'https://credentialtokenvalue123@api.internal';"
    result = agent._audit_hardcoded_secrets(code)
    assert any("URL-embedded credential" in f["issue"] for f in result["findings"])


def test_database_escape_hatch_detection():
    agent = DatabaseArchitectAgent()
    code = "const rows = await prisma.$queryRaw(`SELECT * FROM users WHERE id = ${req.params.id}`)"
    result = agent._review_escape_hatches(code)
    assert result["total_issues"] >= 1


def test_api_graphql_and_rate_limit_contract_detection():
    agent = APIArchitectAgent()
    gql = agent._review_graphql_error_contract(
        "return { errors: [{ message: 'bad' }] }"
    )
    rl = agent._review_rate_limit_contract("res.status(429).json({error:'rate'})")
    assert gql["total_issues"] == 1
    assert rl["total_issues"] == 1


def test_runtime_verification_runs_multiple_detected_commands(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"scripts": {"test": "echo ok", "build": "echo ok", "lint": "echo ok"}}
        )
    )
    (tmp_path / "tsconfig.json").write_text("{}")

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr("agents.cli.subprocess.run", fake_run)
    result = _run_runtime_verification(str(tmp_path), None, 5)
    commands = _project_runtime_commands(str(tmp_path))
    assert result["status"] == "passed"
    assert len(result["checks"]) == len(commands)


def test_runtime_detects_pytest_from_pyproject_without_requirements(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n")
    assert ["pytest", "-q"] in _project_runtime_commands(str(tmp_path))
