"""
Docs Drift Agent — documentation that no longer matches the code.

Docs rot silently: a command gets renamed, a variable gets added, a file gets
moved, and the README keeps describing the repository as it was. Nothing fails,
so nobody finds out until someone follows the instructions and they do not work.

These checks compare the two directly, repository-wide::

    from agents import DocsDriftAgent
    agent = DocsDriftAgent()
    agent._audit_docs_drift(files={"README.md": readme, "agents/cli.py": source})

Each check only speaks when it can see both sides of the comparison, so a
partial view of the repository produces silence rather than noise.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, Callable, Dict, List, Set

from agents.base import BaseAgent

_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt")

#: Only follow links to files a text scan would have collected, so a link to an
#: image or a binary cannot be reported missing just because it was not read.
_CHECKABLE_SUFFIXES = (
    ".md",
    ".mdx",
    ".rst",
    ".txt",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".sh",
    ".sql",
)

_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*(?P<target>[^)\s#]+)")

_FENCE_RE = re.compile(r"```[^\n]*\n(?P<body>.*?)```", re.DOTALL)

#: Reading an environment variable, across the spellings that matter here.
_ENV_READ_RE = re.compile(
    r"""process\.env\.(?P<js>[A-Z][A-Z0-9_]*)"""
    r"""|process\.env\[\s*["'](?P<js_idx>[A-Z][A-Z0-9_]*)["']"""
    r"""|os\.getenv\(\s*["'](?P<py_get>[A-Z][A-Z0-9_]*)["']"""
    r"""|os\.environ(?:\.get)?\(?\[?\s*["'](?P<py_env>[A-Z][A-Z0-9_]*)["']"""
)

#: Provided by the platform, not by a .env file.
_AMBIENT_ENV = {
    "NODE_ENV",
    "PORT",
    "HOME",
    "PATH",
    "PWD",
    "USER",
    "SHELL",
    "LANG",
    "TZ",
    "CI",
    "DEBUG",
    "HOSTNAME",
    "TERM",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "GITHUB_TOKEN",
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "RAILWAY_ENVIRONMENT",
    "VERCEL",
    "VERCEL_ENV",
    "npm_package_version",
}

_ENV_EXAMPLE_NAMES = (".env.example", ".env.sample", ".env.template", "env.example")

#: Where a CLI declares its own name, so documented usage can be checked.
_PY_SCRIPT_RE = re.compile(r"^\s*(?P<name>[\w-]+)\s*=\s*[\"'][\w.]+:\w+", re.MULTILINE)

#: Where subcommands are registered.
_SUBCOMMAND_RE = re.compile(
    r"""add_parser\(\s*["'](?P<argparse>[\w-]+)["']"""
    r"""|\.command\(\s*["'](?P<commander>[\w-]+)"""
    r"""|@\w+\.command\(\s*(?:name\s*=\s*)?["'](?P<click>[\w-]+)["']"""
)


def _finding(severity: str, issue: str, fix: str, **extra: Any) -> Dict[str, Any]:
    finding = {"severity": severity, "issue": issue, "fix": fix}
    finding.update({key: value for key, value in extra.items() if value})
    return finding


def _docs(files: Dict[str, str]) -> Dict[str, str]:
    return {
        path: content
        for path, content in files.items()
        if path.lower().endswith(_DOC_SUFFIXES)
    }


def _code(files: Dict[str, str]) -> Dict[str, str]:
    return {
        path: content
        for path, content in files.items()
        if not path.lower().endswith(_DOC_SUFFIXES)
    }


# ── Broken paths ──────────────────────────────────────────────────────────────


def _check_broken_links(files: Dict[str, str]) -> List[Dict[str, Any]]:
    known = set(files)
    broken: List[str] = []

    for doc_path, content in _docs(files).items():
        base = posixpath.dirname(doc_path)
        for match in _MD_LINK_RE.finditer(content):
            target = match.group("target")
            if re.match(r"^(?:https?:|mailto:|tel:|#|//)", target):
                continue
            if not target.lower().endswith(_CHECKABLE_SUFFIXES):
                continue
            resolved = posixpath.normpath(
                target if target.startswith("/") else posixpath.join(base, target)
            )
            # Strip an exact leading "./" or "/" — never a character set, which
            # would eat the dot of `.github/workflows/ci.yml` and report an
            # existing file as missing.
            if resolved.startswith("./"):
                resolved = resolved[2:]
            resolved = resolved.lstrip("/")
            if resolved not in known:
                broken.append(f"{doc_path} → {target}")

    if broken:
        return [
            _finding(
                "MEDIUM",
                f"{len(broken)} documentation link(s) point at files that do not exist",
                "Update the link or restore the file. A broken path in a README is "
                "usually a rename nobody followed through.",
                evidence="; ".join(sorted(set(broken))[:5]),
            )
        ]
    return []


# ── Environment variables ─────────────────────────────────────────────────────


def _documented_env(files: Dict[str, str]) -> Set[str]:
    documented: Set[str] = set()
    for path, content in files.items():
        if not any(path.endswith(name) for name in _ENV_EXAMPLE_NAMES):
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key = line.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                documented.add(key)
    return documented


def _read_env(files: Dict[str, str]) -> Set[str]:
    used: Set[str] = set()
    for content in _code(files).values():
        for match in _ENV_READ_RE.finditer(content):
            name = next((value for value in match.groupdict().values() if value), None)
            if name:
                used.add(name)
    return used


def _check_env_drift(files: Dict[str, str]) -> List[Dict[str, Any]]:
    documented = _documented_env(files)
    if not documented:
        return []  # nothing to compare against — stay quiet rather than guess

    used = _read_env(files) - _AMBIENT_ENV
    findings: List[Dict[str, Any]] = []

    undocumented = sorted(used - documented)
    if undocumented:
        findings.append(
            _finding(
                "MEDIUM",
                f"{len(undocumented)} environment variable(s) are read by the code but "
                "absent from the example env file — a fresh checkout cannot be "
                "configured from the docs",
                "Add each one to the example file with a placeholder value and a "
                "comment saying what it is for.",
                evidence=", ".join(undocumented[:8]),
            )
        )

    stale = sorted(documented - used)
    if stale:
        findings.append(
            _finding(
                "LOW",
                f"{len(stale)} environment variable(s) are documented but read nowhere "
                "in the code",
                "Remove them, or note that they are consumed by infrastructure rather "
                "than the application — otherwise people keep setting values that do "
                "nothing.",
                evidence=", ".join(stale[:8]),
            )
        )
    return findings


# ── Documented commands ───────────────────────────────────────────────────────


def _cli_names(files: Dict[str, str]) -> Set[str]:
    names: Set[str] = set()
    for path, content in files.items():
        if path.endswith("pyproject.toml") and "[project.scripts]" in content:
            section = content.split("[project.scripts]", 1)[1].split("\n[", 1)[0]
            names.update(
                match.group("name") for match in _PY_SCRIPT_RE.finditer(section)
            )
        if path.endswith("package.json"):
            for match in re.finditer(r'"bin"\s*:\s*\{(?P<body>[^}]*)\}', content):
                names.update(re.findall(r'"([\w-]+)"\s*:', match.group("body")))
    return names


def _registered_subcommands(files: Dict[str, str]) -> Set[str]:
    registered: Set[str] = set()
    for content in _code(files).values():
        for match in _SUBCOMMAND_RE.finditer(content):
            name = next((value for value in match.groupdict().values() if value), None)
            if name:
                registered.add(name)
    return registered


def _check_command_drift(files: Dict[str, str]) -> List[Dict[str, Any]]:
    names = _cli_names(files)
    registered = _registered_subcommands(files)
    if not names or not registered:
        return []  # cannot see both sides — say nothing

    documented: Dict[str, str] = {}
    for doc_path, content in _docs(files).items():
        for fence in _FENCE_RE.finditer(content):
            for line in fence.group("body").splitlines():
                line = line.strip().lstrip("$ ").strip()
                parts = line.split()
                if len(parts) < 2 or parts[0] not in names:
                    continue
                verb = parts[1]
                if re.fullmatch(r"[a-z][\w-]{1,}", verb) and not verb.startswith("-"):
                    documented.setdefault(verb, doc_path)

    missing = sorted(verb for verb in documented if verb not in registered)
    if missing:
        return [
            _finding(
                "HIGH",
                f"{len(missing)} command(s) shown in the docs are not registered in the "
                "CLI — following the README produces an error",
                "Rename the documented command to match the code, or register it. "
                "This is what a rename leaves behind.",
                evidence=", ".join(
                    f"{verb} ({documented[verb]})" for verb in missing[:5]
                ),
            )
        ]
    return []


def run_docs_drift(files: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(_check_command_drift(files))
    findings.extend(_check_env_drift(files))
    findings.extend(_check_broken_links(files))
    return findings


# ── Agent ─────────────────────────────────────────────────────────────────────


class DocsDriftAgent(BaseAgent):
    """Finds documentation that no longer matches the code it describes."""

    name = "docs_drift"
    description = (
        "Finds documentation that has drifted from the code — CLI commands shown "
        "in the README that are not registered, environment variables read but "
        "undocumented (or documented but unread), and doc links pointing at files "
        "that no longer exist."
    )
    model = "gpt-5"

    system_prompt = """\
You compare a repository's documentation against the code it describes.

Drift is silent: nothing fails when a command is renamed, a variable is added, \
or a file is moved. It surfaces when somebody follows the instructions and they \
do not work — usually a new contributor, on their first day.

Check both directions. Documentation promising something the code does not \
provide wastes someone's afternoon. Code requiring something the documentation \
never mentions does the same, and is harder to diagnose.

Only report drift you can see both sides of. If the repository view does not \
include the file that would settle it, say nothing rather than guess.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_docs_drift",
                "description": (
                    "Compare documentation against code across a repository: CLI "
                    "commands, environment variables, and documentation links."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "files": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Mapping of relative file paths to file contents.",
                        }
                    },
                    "required": ["files"],
                },
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_docs_drift": self._audit_docs_drift}

    def _audit_docs_drift(self, files: Dict[str, str]) -> Dict[str, Any]:
        findings = run_docs_drift(files or {})
        return {"findings": findings, "total_issues": len(findings)}


__all__ = ["DocsDriftAgent", "run_docs_drift"]
