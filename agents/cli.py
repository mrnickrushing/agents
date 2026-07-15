"""CLI: deterministic security/code checks without needing an API key.

Use the tool handlers directly for fast, reproducible scanning:

    python -m agents.cli scan path/to/project
    python -m agents.cli scan --file security_review path/to/file.ts
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.code_review import CodeReviewAgent
from agents.database_architect import DatabaseArchitectAgent
from agents.security_audit import SecurityAuditAgent

logger = logging.getLogger(__name__)

# Maximum file size to scan (300KB → 1MB for better coverage)
MAX_FILE_BYTES = 1_000_000

# Severity ranking for sorting
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class CLI:
    """Deterministic scanning without an LLM API key."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.security_agent = SecurityAuditAgent(verbose=verbose)
        self.code_agent = CodeReviewAgent(verbose=verbose)
        self.db_agent = DatabaseArchitectAgent(verbose=verbose)

    def cmd_scan(self, path: str, **kwargs) -> Dict[str, Any]:
        """Scan a project directory or single file."""
        target = Path(path)

        if not target.exists():
            return {"error": f"Path not found: {path}"}

        if target.is_file():
            return self._scan_file(target)
        else:
            return self._scan_directory(target)

    def _scan_file(self, file_path: Path) -> Dict[str, Any]:
        """Scan a single file."""
        try:
            size = file_path.stat().st_size
            if size > MAX_FILE_BYTES:
                return {
                    "error": f"File too large ({size / 1024 / 1024:.1f}MB > {MAX_FILE_BYTES / 1024 / 1024:.1f}MB)",
                    "file": str(file_path),
                }

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read {file_path}: {str(e)}"}

        return self._apply_rules(str(file_path), content)

    def _scan_directory(self, dir_path: Path) -> Dict[str, Any]:
        """Scan a directory recursively."""
        results = []
        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue
            if self._is_test_file(str(file_path)):
                continue
            if self._should_skip(file_path):
                continue
            result = self._scan_file(file_path)
            if "error" not in result or "findings" in result:
                results.append(result)
        return {"files_scanned": len(results), "results": results}

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_exts = {
            ".pyc", ".o", ".so", ".jar", ".zip", ".tar",
            ".png", ".jpg", ".gif", ".pdf", ".exe", ".dll",
        }
        skip_dirs = {"node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv"}
        
        if file_path.suffix.lower() in skip_exts:
            return True
        if any(part in skip_dirs for part in file_path.parts):
            return True
        return False

    def _is_test_file(self, path: str) -> bool:
        """Check if file is a test file."""
        import re
        return bool(re.search(r"(^|/)(?:tests?|__tests__|test_\w+|\w+_test)", path))

    def _apply_rules(self, file_path: str, content: str) -> Dict[str, Any]:
        """Apply all relevant scanning rules to content."""
        findings = []
        ext = Path(file_path).suffix.lower()
        name = Path(file_path).name.lower()

        # Security audit checks
        if ext in {".ts", ".tsx", ".js", ".jsx", ".py"}:
            for tool_name, handler in self.security_agent._tool_handlers.items():
                try:
                    result = handler(content)
                    if isinstance(result, dict) and "findings" in result:
                        for finding in result.get("findings", []):
                            findings.append({
                                "tool": tool_name,
                                "file": file_path,
                                **finding,
                            })
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Tool {tool_name} error on {file_path}: {e}")

        # Code review checks
        if ext in {".ts", ".tsx", ".jsx"}:
            for tool_name, handler in self.code_agent._tool_handlers.items():
                try:
                    result = handler(content)
                    if isinstance(result, dict) and "findings" in result:
                        for finding in result.get("findings", []):
                            findings.append({
                                "tool": tool_name,
                                "file": file_path,
                                **finding,
                            })
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Tool {tool_name} error on {file_path}: {e}")

        # Database checks
        if ("schema" in name or "migration" in name) and ext in {".ts", ".py"}:
            for tool_name, handler in self.db_agent._tool_handlers.items():
                try:
                    result = handler(content)
                    if isinstance(result, dict) and "findings" in result:
                        for finding in result.get("findings", []):
                            findings.append({
                                "tool": tool_name,
                                "file": file_path,
                                **finding,
                            })
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Tool {tool_name} error on {file_path}: {e}")

        return {
            "file": file_path,
            "findings": sorted(
                findings,
                key=lambda f: (SEVERITY_RANK.get(f.get("severity", "INFO"), 99), f.get("tool", "")),
            ),
            "total": len(findings),
        }


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python -m agents.cli scan <path>")
        sys.exit(1)

    cmd = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else "."
    verbose = "--verbose" in sys.argv

    cli = CLI(verbose=verbose)

    if cmd == "scan":
        result = cli.cmd_scan(path)
        print(json.dumps(result, indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
