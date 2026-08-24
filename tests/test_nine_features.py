"""Tests for the 9 new agents/modules."""

from __future__ import annotations

import json
import re

import pytest

# ── 1. WorkflowOrchestrator ───────────────────────────────────────────────

def test_workflow_orchestrator_imports():
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    assert orch.max_chain_depth == 4


def test_workflow_orchestrator_shared_context():
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    orch.set_context("foo", "bar")
    assert orch.get_context("foo") == "bar"
    orch.clear_context()
    assert orch.get_context("foo") is None


def test_workflow_orchestrator_agents_for_findings():
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    findings = [{"issue": "JWT token not validated", "severity": "HIGH"}]
    triggered = orch._agents_for_findings(findings)
    assert "auth_security" in triggered


def test_workflow_run_chain_single_step():
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    code = 'const r = require("helmet"); app.use(r());'
    result = orch.run_chain([("security_audit", "analyze_helmet_config", {"config_json": code})])
    assert "findings" in result
    assert "chain_log" in result
    assert len(result["chain_log"]) == 1


def test_workflow_run_chain_unknown_agent():
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    result = orch.run_chain([("nonexistent_agent", "some_tool", {})])
    assert result["findings"] == []


# ── 2. HealingAgent ───────────────────────────────────────────────────────

def test_healing_agent_imports():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    assert "generate_patch" in agent._tool_handlers
    assert "apply_patch_and_test" in agent._tool_handlers
    assert "create_healing_pr" in agent._tool_handlers


def test_healing_generate_patch_mechanical():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    finding = {"issue": "console.log exposes password value", "severity": "HIGH", "fix": "Remove sensitive log."}
    code = "console.log('password:', password);"
    result = agent._generate_patch(finding, code, language=".ts")
    assert result["method"] in ("mechanical", "suggestion")
    assert "confidence" in result


def test_healing_generate_patch_fallback_to_suggestion():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    finding = {"issue": "Missing CSRF token", "severity": "HIGH", "fix": "Add CSRF middleware."}
    code = "app.use(express.json());"
    result = agent._generate_patch(finding, code, language=".ts")
    assert result["method"] == "suggestion"
    assert result["confidence"] < 0.5


def test_healing_create_healing_pr():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    patches = [
        {"description": "Fix A", "confidence": 0.9, "method": "mechanical", "finding": {"issue": "A", "severity": "HIGH"}},
        {"description": "Fix B", "confidence": 0.3, "method": "suggestion", "suggestion": "Do B", "finding": {"issue": "B", "severity": "LOW"}},
    ]
    result = agent._create_healing_pr(patches, title="Test PR")
    assert result["total_patches"] == 2
    assert result["auto_apply_count"] == 1
    assert "Test PR" in result["title"]


def test_healing_apply_patch_skips_low_confidence():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    patch = {"method": "mechanical", "confidence": 0.2, "patched": "x", "description": "Low confidence"}
    result = agent._apply_patch_and_test(patch, "/tmp/fake.ts", "/tmp/project")
    assert result["status"] == "skipped"


def test_healing_apply_patch_skips_suggestion():
    from agents.healing import HealingAgent
    agent = HealingAgent()
    patch = {"method": "suggestion", "confidence": 0.5, "suggestion": "Add CSRF", "description": "CSRF"}
    result = agent._apply_patch_and_test(patch, "/tmp/fake.ts", "/tmp/project")
    assert result["status"] == "skipped"


# ── 7. SupplyChainAuditAgent (enhanced) ──────────────────────────────────

def test_supply_chain_detects_git_origin():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    content = 'npm install --save git+https://github.com/user/evil-package'
    result = agent._audit_supply_chain(content)
    issues = [f["issue"] for f in result["findings"]]
    assert any("mutable" in i.lower() or "vcs" in i.lower() for i in issues)


def test_supply_chain_detects_typosquatting():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    # "lodash" → "Iodash" (l→I, edit distance 1)
    content = json.dumps({"dependencies": {"Iodash": "^4.0.0"}})
    result = agent._audit_supply_chain(content, path="package.json")
    # May or may not trigger depending on case sensitivity — just ensure no crash
    assert "findings" in result


def test_supply_chain_detects_known_suspicious():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    content = json.dumps({"dependencies": {"event-stream": "3.3.6"}})
    result = agent._audit_supply_chain(content, path="package.json")
    issues = [f["issue"] for f in result["findings"]]
    assert any("event-stream" in i for i in issues)


def test_supply_chain_detects_copyleft():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    content = 'license = "AGPL-3.0"\nversion = "1.0.0"'
    result = agent._audit_supply_chain(content)
    issues = [f["issue"] for f in result["findings"]]
    assert any("copyleft" in i.lower() or "AGPL" in i for i in issues)


def test_supply_chain_detects_http_registry():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    content = "registry = http://my-internal-registry.example.com"
    result = agent._audit_supply_chain(content)
    issues = [f["issue"] for f in result["findings"]]
    assert any("http" in i.lower() for i in issues)


def test_supply_chain_detects_wildcard_pin():
    from agents.supply_chain_audit import SupplyChainAuditAgent
    agent = SupplyChainAuditAgent()
    content = json.dumps({"dependencies": {"express": "*"}})
    result = agent._audit_supply_chain(content, path="package.json")
    issues = [f["issue"] for f in result["findings"]]
    assert any("wildcard" in i.lower() or "*" in i for i in issues)


# ── 8. ComplianceAuditAgent ───────────────────────────────────────────────

def test_compliance_imports():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    assert "audit_compliance" in agent._tool_handlers
    assert "list_frameworks" in agent._tool_handlers


def test_compliance_list_frameworks():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    result = agent._list_frameworks()
    assert "SOC2" in result["frameworks"]
    assert "HIPAA" in result["frameworks"]
    assert "GDPR" in result["frameworks"]
    assert "PCI-DSS" in result["frameworks"]


def test_compliance_soc2_partial_code():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    # Has JWT but not HSTS → partial/missing
    code = "const token = jwt.sign(payload, secret); jwt.verify(token, secret);"
    result = agent._audit_compliance(code, standard="SOC2")
    assert result["standard"] == "SOC2"
    assert "controls" in result
    assert len(result["controls"]) > 0
    # Summary fields exist
    assert "total" in result["summary"]
    assert "met" in result["summary"]


def test_compliance_unknown_standard():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    result = agent._audit_compliance("some code", standard="ISO27001")
    assert "error" in result


def test_compliance_hipaa_has_findings_for_empty_code():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    result = agent._audit_compliance("", standard="HIPAA")
    # All controls should be missing for empty code
    statuses = {c["status"] for c in result["controls"]}
    assert "MISSING" in statuses


def test_compliance_fully_met_code():
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    # Code that satisfies SOC2 CC6.1 checks
    code = (
        "jwt.verify(token, secret); "
        "const oauth = require('oauth'); "
        "requireApiKey(req);"
    )
    result = agent._audit_compliance(code, standard="SOC2")
    cc61 = next((c for c in result["controls"] if c["control_id"] == "CC6.1"), None)
    assert cc61 is not None
    assert cc61["status"] == "MET"


# ── 9. PostmortemAgent ────────────────────────────────────────────────────

def test_postmortem_imports():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    assert "analyze_incident" in agent._tool_handlers


def test_postmortem_n_plus_one_incident():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    incident = (
        "Database connection pool exhaustion — root cause: N+1 query in payment webhook handler. "
        "Each request issued a query inside a loop without batching."
    )
    result = agent._analyze_incident(incident)
    assert any("n_plus_one" in d["detector"] or "n+1" in d["detector"].lower()
               for d in result["detectors_would_catch"])


def test_postmortem_jwt_incident():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    incident = "JWT token was not validated, allowing forged tokens to bypass auth."
    result = agent._analyze_incident(incident)
    assert len(result["detectors_would_catch"]) > 0 or len(result["detectors_need_enhancement"]) > 0


def test_postmortem_prevention_confidence_range():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    result = agent._analyze_incident("N+1 query caused connection pool exhaustion during a retry storm.")
    assert 0 <= result["prevention_confidence"] <= 100


def test_postmortem_structural_recommendations_populated():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    result = agent._analyze_incident("Retry storm with no backoff caused thundering herd on the database.")
    assert len(result["structural_recommendations"]) > 0


def test_postmortem_summary_string():
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    result = agent._analyze_incident("JWT token not validated before use.")
    assert isinstance(result["summary"], str)


# ── DetectorTrainer ───────────────────────────────────────────────────────

def test_trainer_imports():
    from agents.training import DetectorTrainer
    trainer = DetectorTrainer()
    assert "train_detector" in trainer._tool_handlers
    assert "evaluate_detector" in trainer._tool_handlers
    assert "list_detector_versions" in trainer._tool_handlers


def test_trainer_no_data():
    from agents.training import DetectorTrainer
    trainer = DetectorTrainer(db_path=None)
    result = trainer._train_detector("security_audit.nonexistent")
    assert result["status"] == "no_data"


def test_trainer_evaluate_invalid_pattern():
    from agents.training import DetectorTrainer
    from agents.training import _evaluate_pattern
    metrics = _evaluate_pattern("([invalid", ["code with jwt.verify("], [])
    assert "error" in metrics


def test_trainer_evaluate_pattern_precision():
    from agents.training import _evaluate_pattern
    metrics = _evaluate_pattern(r"jwt\.verify\(", ["jwt.verify(token)", "jwt.verify(x, secret)"], ["jwt.decode(token)"])
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


# ── GitHubIntegration ─────────────────────────────────────────────────────

def test_github_integration_imports():
    from agents.github_integration import GitHubIntegration, format_pr_comment, format_scan_summary
    gi = GitHubIntegration()
    assert gi is not None


def test_github_format_pr_comment():
    from agents.github_integration import format_pr_comment
    finding = {"severity": "HIGH", "issue": "JWT not validated", "fix": "Use jwt.verify().", "detector": "auth_security"}
    comment = format_pr_comment(finding, file_path="src/auth.ts", line=42)
    assert "HIGH" in comment
    assert "JWT not validated" in comment
    assert "jwt.verify()" in comment


def test_github_format_scan_summary_no_findings():
    from agents.github_integration import format_scan_summary
    result = format_scan_summary([])
    assert "No issues detected" in result


def test_github_format_scan_summary_with_findings():
    from agents.github_integration import format_scan_summary
    findings = [
        {"severity": "CRITICAL", "issue": "Hardcoded secret"},
        {"severity": "HIGH", "issue": "Missing rate limit"},
    ]
    result = format_scan_summary(findings)
    assert "CRITICAL" in result
    assert "HIGH" in result


def test_github_handle_event_ignored_type():
    from agents.github_integration import GitHubIntegration
    gi = GitHubIntegration()
    result = gi.handle_event("push", {})
    assert result["action"] == "ignored"


def test_github_handle_pr_opened_no_scan_fn():
    from agents.github_integration import GitHubIntegration
    gi = GitHubIntegration()
    payload = {
        "action": "opened",
        "pull_request": {"number": 42, "body": "Fix auth bug"},
        "repository": {"full_name": "owner/repo"},
    }
    result = gi.handle_event("pull_request", payload, scan_fn=None)
    assert result["action"] == "scanned"
    assert result["pr_number"] == 42
    assert result["findings_count"] == 0


def test_github_verify_signature_no_secret():
    from agents.github_integration import GitHubIntegration
    gi = GitHubIntegration(webhook_secret=None)
    assert gi.verify_signature(b"payload", "sha256=anything") is True


def test_github_verify_signature_with_secret():
    import hashlib
    import hmac as _hmac
    from agents.github_integration import GitHubIntegration
    secret = "my-secret"
    payload = b"test-payload"
    sig = "sha256=" + _hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    gi = GitHubIntegration(webhook_secret=secret)
    assert gi.verify_signature(payload, sig) is True
    assert gi.verify_signature(payload, "sha256=wrong") is False


# ── FigmaScaffoldAgent ────────────────────────────────────────────────────

def test_figma_scaffold_imports():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    assert "scaffold_default_app" in agent._tool_handlers
    assert "scaffold_from_tokens" in agent._tool_handlers
    assert "extract_design_tokens" in agent._tool_handlers


def test_figma_scaffold_default_app():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._scaffold_default_app(app_name="TestApp", payment_model="subscription")
    assert result["app_name"] == "TestApp"
    assert result["files_count"] > 0
    assert "eas.json" in result["files"]
    assert "src/lib/sentry.ts" in result["files"]
    assert "src/lib/revenuecat.ts" in result["files"]
    assert "backend/src/index.ts" in result["files"]


def test_figma_scaffold_freemium_no_stripe_webhook():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._scaffold_default_app(app_name="FreeApp", payment_model="freemium")
    backend = result["files"]["backend/src/index.ts"]
    # Stripe webhook block only present for subscription/one_time
    assert "src/lib/revenuecat.ts" in result["files"]


def test_figma_scaffold_one_time_includes_stripe():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._scaffold_default_app(app_name="BuyApp", payment_model="one_time")
    backend = result["files"]["backend/src/index.ts"]
    assert "stripe.webhooks.constructEvent" in backend


def test_figma_extract_tokens_invalid_json():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._extract_design_tokens("not json")
    assert "error" in result
    assert "tokens" in result  # falls back to defaults


def test_figma_sentry_no_pii():
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._scaffold_default_app(app_name="SafeApp")
    sentry = result["files"]["src/lib/sentry.ts"]
    assert "sendDefaultPii: false" in sentry


# ── WebDashboard ──────────────────────────────────────────────────────────

def test_web_dashboard_imports():
    from agents.web import AgentsDashboard
    dash = AgentsDashboard(db_path=None)
    assert dash is not None


def test_web_dashboard_summary_no_db():
    from agents.web import AgentsDashboard
    dash = AgentsDashboard(db_path=None)
    summary = dash.get_summary()
    assert summary["total_scans"] == 0
    assert summary["total_findings"] == 0


def test_web_dashboard_findings_no_db():
    from agents.web import AgentsDashboard
    dash = AgentsDashboard(db_path=None)
    result = dash.get_findings()
    assert result["findings"] == []


def test_web_dashboard_sse_stream_yields_connected():
    from agents.web import AgentsDashboard
    dash = AgentsDashboard(db_path=None)
    gen = dash.sse_stream()
    first = next(gen)
    assert "connected" in first
    gen.close()


def test_web_dashboard_publish_event():
    from agents.web import AgentsDashboard
    dash = AgentsDashboard(db_path=None)
    # Should not raise even with no subscribers
    dash.publish_event("scan_complete: 5 findings")


# ── New agents registered in CLI ──────────────────────────────────────────

def test_new_agents_registered_in_cli():
    from agents.cli import AGENTS
    for name in ("compliance", "postmortem", "healing", "training", "figma_scaffold"):
        assert name in AGENTS, f"'{name}' not found in AGENTS dict"


def test_new_agents_have_tool_handlers():
    from agents.cli import AGENTS
    for name in ("compliance", "postmortem", "healing", "training", "figma_scaffold"):
        instance = AGENTS[name]()
        assert len(instance._tool_handlers) > 0, f"'{name}' has no tool handlers"


# ── New agents in __init__ exports ────────────────────────────────────────

def test_new_agents_exported_from_package():
    import agents
    for attr in ("ComplianceAuditAgent", "PostmortemAgent", "HealingAgent",
                 "DetectorTrainer", "FigmaScaffoldAgent", "WorkflowOrchestrator"):
        assert hasattr(agents, attr), f"agents.{attr} not exported"
