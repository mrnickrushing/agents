"""
Self-Healing Agent — patch generation and auto-apply with test validation.

HealingAgent attempts to patch findings produced by `agents.cli scan`,
validates each patch by running the project's test suite, and either
applies confirmed fixes or stages them for review.

Usage:
    from agents.healing import HealingAgent
    healer = HealingAgent()
    result = healer.generate_patch(finding, code)
    healer.apply_patch_and_test(result["patch"], project_path)
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent

logger = logging.getLogger(__name__)

# Maps finding keyword → (search_pattern, replacement_template)
# These are high-confidence mechanical fixes that need no LLM.
_MECHANICAL_FIXES: List[Dict[str, Any]] = [
    {
        "keywords": ["helmet"],
        "description": "Enable Helmet security headers",
        "confidence": 0.9,
        "search": r"app\.use\(helmet\(\)\)",
        "replace": "app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } }, hsts: { maxAge: 31536000, includeSubDomains: true } }))",
        "languages": [".ts", ".js"],
    },
    {
        "keywords": ["console.log", "logging", "password", "secret"],
        "description": "Remove sensitive data from logs",
        "confidence": 0.85,
        "search": r"console\.log\([^)]*(?:password|secret|token)[^)]*\)",
        "replace": "// [redacted — sensitive value removed from log]",
        "languages": [".ts", ".js"],
    },
    {
        "keywords": ["eval(", "eval ("],
        "description": "Remove dangerous eval() call",
        "confidence": 0.75,
        "search": r"\beval\s*\(([^)]+)\)",
        "replace": r"JSON.parse(\1)  // TODO: replace eval with safe alternative",
        "languages": [".ts", ".js"],
    },
    {
        "keywords": ["httponly", "samesite", "secure cookie"],
        "description": "Harden cookie settings",
        "confidence": 0.8,
        "search": r"(res\.cookie\([^,]+,\s*[^,]+)(,\s*\{[^}]*\})?(\))",
        "replace": r"\1, { httpOnly: true, secure: true, sameSite: 'strict' }\3",
        "languages": [".ts", ".js"],
    },
]


class HealingAgent(BaseAgent):
    """
    Self-healing agent that turns scan findings into code patches,
    validates them against the project test suite, and either applies
    or stages them for PR review.
    """

    name = "healing"
    description = "Generates, validates, and applies code patches for scan findings."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "generate_patch",
                "description": "Generate a code patch for a single scan finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding": {
                            "type": "object",
                            "description": "A finding dict with 'issue', 'severity', 'fix' keys",
                        },
                        "code": {
                            "type": "string",
                            "description": "Source code to patch",
                        },
                        "language": {
                            "type": "string",
                            "description": "File extension, e.g. '.ts'",
                        },
                    },
                    "required": ["finding", "code"],
                },
            },
            {
                "name": "apply_patch_and_test",
                "description": "Apply a patch to a file and run the project test suite.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "patch": {
                            "type": "object",
                            "description": "Patch dict from generate_patch",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to patch",
                        },
                        "project_path": {
                            "type": "string",
                            "description": "Project root for running tests",
                        },
                    },
                    "required": ["patch", "file_path", "project_path"],
                },
            },
            {
                "name": "create_healing_pr",
                "description": "Describe a healing PR for uncertain fixes.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "patches": {"type": "array", "items": {"type": "object"}},
                        "title": {"type": "string"},
                    },
                    "required": ["patches"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "generate_patch": self._generate_patch,
            "apply_patch_and_test": self._apply_patch_and_test,
            "create_healing_pr": self._create_healing_pr,
        }

    # ── Tool handlers ─────────────────────────────────────────────────

    def _generate_patch(
        self,
        finding: Dict[str, Any],
        code: str,
        language: str = ".ts",
    ) -> Dict[str, Any]:
        """Attempt a mechanical fix; fall back to LLM suggestion."""
        issue = str(finding.get("issue", "")).lower()
        fix_hint = str(finding.get("fix", ""))

        for rule in _MECHANICAL_FIXES:
            if language not in rule["languages"]:
                continue
            if any(kw in issue for kw in rule["keywords"]):
                patched, n = re.subn(rule["search"], rule["replace"], code, count=1)
                if n:
                    return {
                        "description": rule["description"],
                        "confidence": rule["confidence"],
                        "original": code,
                        "patched": patched,
                        "method": "mechanical",
                        "finding": finding,
                    }

        # No mechanical rule matched — return a suggestion only.
        return {
            "description": fix_hint or "Manual fix required",
            "confidence": 0.3,
            "original": code,
            "patched": code,
            "method": "suggestion",
            "suggestion": fix_hint,
            "finding": finding,
        }

    def _apply_patch_and_test(
        self,
        patch: Dict[str, Any],
        file_path: str,
        project_path: str,
    ) -> Dict[str, Any]:
        """Apply a patch to ``file_path`` and run tests under ``project_path``."""
        if patch.get("method") == "suggestion":
            return {
                "status": "skipped",
                "reason": "Patch is a suggestion only (confidence too low for auto-apply)",
                "suggestion": patch.get("suggestion", ""),
            }

        if patch["confidence"] < 0.5:
            return {
                "status": "skipped",
                "reason": f"Confidence {patch['confidence']:.0%} below threshold",
            }

        try:
            with open(file_path, "r", errors="ignore") as fh:
                original_content = fh.read()

            with open(file_path, "w") as fh:
                fh.write(patch["patched"])

            test_result = _run_tests(project_path)
            if test_result["passed"]:
                return {
                    "status": "applied",
                    "file": file_path,
                    "tests": test_result,
                    "description": patch["description"],
                }
            else:
                # Revert
                with open(file_path, "w") as fh:
                    fh.write(original_content)
                return {
                    "status": "reverted",
                    "reason": "Tests failed after applying patch",
                    "tests": test_result,
                }
        except OSError as exc:
            return {"status": "error", "reason": str(exc)}

    def _create_healing_pr(
        self,
        patches: List[Dict[str, Any]],
        title: str = "Auto-healing patches from agents scan",
    ) -> Dict[str, Any]:
        """Return a structured PR description for uncertain patches."""
        lines = [f"# {title}\n"]
        for i, patch in enumerate(patches, 1):
            desc = patch.get("description", "Unknown fix")
            conf = patch.get("confidence", 0)
            finding = patch.get("finding", {})
            lines.append(
                f"## Fix {i}: {desc} (confidence: {conf:.0%})\n"
                f"**Finding**: {finding.get('issue', 'N/A')}\n"
                f"**Severity**: {finding.get('severity', 'N/A')}\n"
            )
            if patch.get("method") == "mechanical":
                lines.append("**Status**: Ready to auto-apply after PR approval\n")
            else:
                lines.append(f"**Suggested fix**: {patch.get('suggestion', '')}\n")
        return {
            "title": title,
            "body": "\n".join(lines),
            "patches": patches,
            "total_patches": len(patches),
            "auto_apply_count": sum(
                1 for p in patches if p.get("confidence", 0) >= 0.8
            ),
        }


# ── Helpers ───────────────────────────────────────────────────────────


def _run_tests(project_path: str) -> Dict[str, Any]:
    """Run the project's test suite and return a result dict."""
    from agents.cli import _project_runtime_commands

    commands = _project_runtime_commands(project_path)
    test_commands = [
        cmd
        for cmd in commands
        if any(part == "test" or "pytest" in part for part in cmd)
    ]

    if not test_commands:
        return {
            "passed": False,
            "output": "No test commands detected; patch was not validated",
            "commands": [],
        }

    cmd = test_commands[0]
    try:
        proc = subprocess.run(
            cmd,
            cwd=project_path,
            shell=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "passed": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-2000:] if proc.stdout else "",
            "stderr": proc.stderr[-2000:] if proc.stderr else "",
            "command": cmd,
        }
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"passed": False, "error": str(exc), "command": cmd}
