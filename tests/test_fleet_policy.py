"""Fleet policy tests.

Every fixture here is modelled on the real config that carried the bug, so a
passing test means the rule catches the thing it was written for — not a
synthetic shape that happens to satisfy the regex.
"""

from __future__ import annotations

import json

from agents import FleetPolicyAgent as ExportedFleetPolicyAgent
from agents.fleet_policy import (
    FleetPolicyAgent,
    check_dependabot_grouping,
    check_forced_version_without_dependabot_ignore,
    check_plaintext_secrets,
    check_trivy_sarif_gate,
    check_workflow_concurrency,
    run_policies,
)

# The shape that silently ignored its own severity filter in five repos.
TRIVY_BROKEN = """
jobs:
  trivy:
    steps:
      - name: Trivy scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          format: sarif
          output: trivy.sarif
          severity: HIGH,CRITICAL
          exit-code: 1
"""

# The fix: blocking table gate + separate non-blocking sarif upload.
TRIVY_FIXED = """
jobs:
  trivy:
    steps:
      - name: Trivy gate
        uses: aquasecurity/trivy-action@0.28.0
        with:
          format: table
          severity: HIGH,CRITICAL
          exit-code: 1
      - name: Trivy sarif upload
        uses: aquasecurity/trivy-action@0.28.0
        with:
          format: sarif
          output: trivy.sarif
"""


def test_trivy_sarif_gate_is_flagged():
    out = check_trivy_sarif_gate(".github/workflows/security-scan.yml", TRIVY_BROKEN)
    assert len(out) == 1
    assert out[0].rule == "trivy-sarif-gate"
    assert out[0].severity == "HIGH"


def test_fleet_policy_agent_is_exported_and_wraps_findings():
    assert ExportedFleetPolicyAgent is FleetPolicyAgent
    result = FleetPolicyAgent().run_fleet_policies(
        {".github/workflows/security-scan.yml": TRIVY_BROKEN}
    )
    assert result["total_issues"] >= 1


def test_trivy_split_gate_is_clean():
    assert check_trivy_sarif_gate(".github/workflows/security-scan.yml", TRIVY_FIXED) == []


def test_workflow_without_concurrency_is_flagged():
    wf = "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\n\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    out = check_workflow_concurrency(".github/workflows/ci.yml", wf)
    assert len(out) == 1
    assert out[0].rule == "workflow-missing-concurrency"


def test_workflow_with_concurrency_is_clean():
    wf = ("name: CI\non:\n  push:\n    branches: [main]\n\n"
          "concurrency:\n  group: x\n  cancel-in-progress: true\n\njobs:\n  test:\n")
    assert check_workflow_concurrency(".github/workflows/ci.yml", wf) == []


def test_cron_only_workflow_is_not_flagged():
    # Nothing supersedes a scheduled run, so concurrency buys nothing.
    wf = "name: Nightly\non:\n  schedule:\n    - cron: '0 3 * * *'\n\njobs:\n  x:\n"
    assert check_workflow_concurrency(".github/workflows/nightly.yml", wf) == []


DEPENDABOT_UNGROUPED = """
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/backend"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
"""


def test_ungrouped_ecosystems_are_flagged_but_actions_are_not():
    out = check_dependabot_grouping(".github/dependabot.yml", DEPENDABOT_UNGROUPED)
    ecos = " ".join(f.message for f in out)
    assert len(out) == 2          # npm + pip
    assert "npm" in ecos and "pip" in ecos
    assert "github-actions" not in ecos


def test_grouped_ecosystem_is_clean():
    y = ('version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n'
         '    schedule:\n      interval: "weekly"\n    groups:\n      minor:\n'
         '        patterns: ["*"]\n        update-types: ["minor", "patch"]\n')
    assert check_dependabot_grouping(".github/dependabot.yml", y) == []


def test_real_token_in_ci_config_is_flagged():
    # Modelled on a build config found with a live token committed to main.
    yml = 'environment:\n  vars:\n    EXPO_TOKEN: "0jmTCQH3xPGBbv_LC-D9jYK8Gppf5ya1e6323T-E"\n'
    out = check_plaintext_secrets("codemagic.yaml", yml)
    assert len(out) == 1
    assert out[0].severity == "HIGH"
    assert "EXPO_TOKEN" in out[0].message


def test_secret_references_are_not_flagged():
    yml = (
        'env:\n'
        '  API_TOKEN: ${{ secrets.API_TOKEN }}\n'
        '  OTHER_SECRET: "$MY_ENV_VAR"\n'
        '  SOME_KEY: "your-key-here-placeholder"\n'
        '  EXAMPLE_TOKEN: "example-value-not-real-xxxx"\n'
    )
    assert check_plaintext_secrets(".github/workflows/ci.yml", yml) == []


def test_known_token_shapes_are_flagged():
    for blob, _ in [
        ("token: ghp_" + "a" * 36, "gh"),
        ("key: AKIAIOSFODNN7EXAMPLE", "aws"),
        ("-----BEGIN RSA PRIVATE KEY-----", "pem"),
    ]:
        assert check_plaintext_secrets("Dockerfile", blob), blob


def test_direct_dependency_holdback_without_ignore_is_flagged():
    pkg = json.dumps({
        "devDependencies": {"postcss": "^8.5.26", "nanoid": "^3.3.18"},
        "overrides": {"postcss": "8.5.26", "nanoid": "^3.3.18"},
    })
    out = check_forced_version_without_dependabot_ignore(pkg, "version: 2\nupdates: []\n")
    assert {f.message.split()[0] for f in out} == {"postcss", "nanoid"}


def test_transitive_only_override_is_not_flagged():
    # The case that made this rule useless: an override forcing a patched
    # version deep in the tree. Dependabot does not open version-update PRs
    # for transitive packages, so an ignore would match nothing. 28 of these
    # were reported across the real fleet before this was narrowed.
    pkg = json.dumps({"dependencies": {"react": "^18.2.0"},
                      "overrides": {"postcss": "8.5.26"}})
    assert check_forced_version_without_dependabot_ignore(pkg, "updates: []") == []


def test_forced_version_with_matching_ignore_is_clean():
    pkg = json.dumps({"devDependencies": {"postcss": "^8.5.26"},
                      "overrides": {"postcss": "8.5.26"}})
    dep = 'updates:\n  - ignore:\n      - dependency-name: "postcss"\n'
    assert check_forced_version_without_dependabot_ignore(pkg, dep) == []


def test_wildcard_ignore_matches_prefix():
    pkg = json.dumps({"dependencies": {"@radix-ui/react-slot": "^1.3.3"},
                      "resolutions": {"@radix-ui/react-slot": "1.3.3"}})
    dep = 'updates:\n  - ignore:\n      - dependency-name: "@radix-ui/*"\n'
    assert check_forced_version_without_dependabot_ignore(pkg, dep) == []


def test_plain_caret_dependency_is_not_flagged():
    # The deliberately-out-of-scope case: a plain range is not evidence of
    # intent, and flagging every dependency would make the rule useless.
    pkg = json.dumps({"dependencies": {"react": "^18.2.0", "lodash": "^4.17.21"}})
    assert check_forced_version_without_dependabot_ignore(pkg, "") == []


def test_run_policies_dispatches_and_sorts_by_severity():
    findings = run_policies({
        ".github/workflows/security-scan.yml": TRIVY_BROKEN,
        ".github/workflows/ci.yml": "on:\n  push:\n\njobs:\n  t:\n",
        ".github/dependabot.yml": DEPENDABOT_UNGROUPED,
        "package.json": json.dumps({
            "devDependencies": {"postcss": "^8.5.26"},
            "overrides": {"postcss": "8.5.26"},
        }),
    })
    rules = [f.rule for f in findings]
    assert "trivy-sarif-gate" in rules
    assert "workflow-missing-concurrency" in rules
    assert "dependabot-missing-grouping" in rules
    assert "forced-version-without-dependabot-ignore" in rules
    # HIGH first — the ordering is what makes the report readable.
    assert findings[0].severity == "HIGH"


def test_run_policies_on_clean_fleet_returns_nothing():
    assert run_policies({
        ".github/workflows/security-scan.yml": TRIVY_FIXED.replace(
            "jobs:", "concurrency:\n  group: x\n  cancel-in-progress: true\n\njobs:"),
    }) == []


def test_unparseable_files_are_reported_not_swallowed():
    # A parser that returns [] on malformed input turns the whole checker into
    # a silent no-op — which is exactly what happened when PyYAML was missing
    # from the dependency list and `except Exception` ate the ImportError.
    findings = run_policies({
        ".github/dependabot.yml": "{{{ not yaml",
        "package.json": "not json at all",
    })
    assert [f.rule for f in findings] == ["dependabot-unparseable"]


def test_yaml_is_a_hard_dependency():
    # Guards the regression directly: if PyYAML ever falls out of
    # install_requires again, this fails loudly instead of the grouping rule
    # quietly reporting every repo as clean.
    import agents.fleet_policy as fp
    assert fp.yaml is not None


def test_override_target_handles_scopes_and_nesting():
    from agents.fleet_policy import _override_target
    # Naive rsplit("/") mangles scoped packages, which then silently fail to
    # match a "@scope/*" ignore — a false positive on an already-covered pin.
    assert _override_target("@radix-ui/react-slot") == "@radix-ui/react-slot"
    assert _override_target("**/@radix-ui/react-slot") == "@radix-ui/react-slot"
    assert _override_target("**/@svgr/plugin-svgo/svgo") == "svgo"
    assert _override_target("parent/child") == "child"
    assert _override_target("**/pkg") == "pkg"
    assert _override_target("pkg") == "pkg"
    # npm override keys may carry a version range; the range is not part of
    # the package name, and emitting it would produce a dependabot ignore
    # that matches nothing.
    assert _override_target("zod@<4.4.0") == "zod"
    assert _override_target("@babel/core@^7.1.0") == "@babel/core"


def test_holdback_rule_is_silent_without_a_dependabot_config():
    # With no dependabot config nothing can bump past the pin, so the finding
    # is not actionable — and "fixing" it would mean adding a config, which
    # starts generating PRs and CI spend instead of protecting anything.
    findings = run_policies({"package.json": json.dumps({
        "devDependencies": {"postcss": "^8.5.26"},
        "overrides": {"postcss": "8.5.26"},
    })})
    assert findings == []


def test_holdback_rule_fires_when_dependabot_is_configured():
    findings = run_policies({
        "package.json": json.dumps({
            "devDependencies": {"postcss": "^8.5.26"},
            "overrides": {"postcss": "8.5.26"},
        }),
        ".github/dependabot.yml": 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n'
                                  '    directory: "/"\n    schedule:\n      interval: "weekly"\n'
                                  '    groups:\n      m:\n        patterns: ["*"]\n',
    })
    assert [f.rule for f in findings] == ["forced-version-without-dependabot-ignore"]


TRIVY_SARIF_BUT_LIMITED = """
jobs:
  trivy:
    steps:
      - uses: aquasecurity/trivy-action@v0.36.0
        with:
          severity: HIGH,CRITICAL
          limit-severities-for-sarif: true
          exit-code: '1'
          format: sarif
"""


def test_sarif_with_limit_severities_is_not_flagged():
    # trivy-action's documented escape hatch: with limit-severities-for-sarif
    # the severity filter *is* honoured in sarif mode, so the gate is correct.
    # Flagging it sent me to "fix" a repo that was already right.
    assert check_trivy_sarif_gate(".github/workflows/security-scan.yml",
                                  TRIVY_SARIF_BUT_LIMITED) == []
