"""
PR Review Agent — graph-indexed, swarm-based pull request review.

Reviews a pull request the way a senior engineer would: with the whole
codebase in view, not just the diff.

Three stages:

1. **Index.** :class:`~agents.knowledge_graph.CodebaseGraph` parses the repo
   into files, functions, classes, imports, calls, and data flows.
2. **Swarm.** Specialist reviewers run in parallel over the diff — logic,
   security, performance, cross-file impact, convention drift, custom rules,
   and test coverage — each citing graph evidence for what it flags.
3. **Learn.** Verdicts recorded through :mod:`agents.evolution` feed back in,
   so categories a team keeps dismissing get suppressed while security
   findings never do.

The output mirrors a full PR review: a plain-language summary, a 0–5
confidence score, an issues table, a Mermaid diagram chosen to fit the change,
and inline comments carrying P0/P1/P2 severity badges with suggested fixes.

Usage::

    from agents.pr_review import PRReviewAgent

    agent = PRReviewAgent()
    review = agent.review_pull_request(diff=diff_text, repo_path=".")
    print(review["markdown"])

No API key is required — every reviewer in the swarm is deterministic. Set
``OPENAI_API_KEY`` or ``ANTHROPIC_API_KEY`` to additionally use the agent
conversationally.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agents.base import BaseAgent
from agents.review_config import (
    ReviewConfig,
    Rule,
    load_review_config,
    matches_any_glob,
)

logger = logging.getLogger(__name__)

# ── Severity model ────────────────────────────────────────────────────────────

#: Severity badges, most severe first.
SEVERITIES = ("P0", "P1", "P2")

SEVERITY_LABELS = {
    "P0": "Critical",
    "P1": "High",
    "P2": "Medium",
}

SEVERITY_BLURB = {
    "P0": "Security vulnerabilities, data loss, crashes — must fix before merging",
    "P1": "Bugs, incorrect behaviour, edge cases — should fix",
    "P2": "Code quality, maintainability, best practices — consider fixing",
}

#: Maps the severity vocabulary used by this toolkit's detectors onto badges.
_DETECTOR_SEVERITY_TO_BADGE = {
    "CRITICAL": "P0",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P2",
    "INFO": "P2",
}

_SEVERITY_RANK = {badge: index for index, badge in enumerate(SEVERITIES)}

#: Risk ladder for the auto-approve ceiling, keyed by worst severity present.
_SEVERITY_TO_RISK = {"P0": "critical", "P1": "high", "P2": "medium"}

_RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Strictness gates: (allowed badges, minimum confidence per badge).
_STRICTNESS_GATES: Dict[int, Dict[str, float]] = {
    1: {"P0": 0.0, "P1": 0.0, "P2": 0.0},  # verbose — surface everything
    2: {"P0": 0.0, "P1": 0.45, "P2": 0.65},  # balanced default
    3: {"P0": 0.0, "P1": 0.75},  # critical only — P2 is dropped entirely
}

_MAX_DIFF_BYTES = 4 * 1024 * 1024
_MAX_FILE_BYTES = 1024 * 1024


# ── Diff parsing ──────────────────────────────────────────────────────────────


@dataclass
class DiffLine:
    """One line inside a hunk. ``new_lineno`` is set for context and additions."""

    kind: str  # "add" | "remove" | "context"
    text: str
    new_lineno: Optional[int] = None
    old_lineno: Optional[int] = None


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    heading: str
    lines: List[DiffLine] = field(default_factory=list)


@dataclass
class FileDiff:
    """The changes to one file, with enough structure to anchor comments."""

    path: str
    old_path: str = ""
    status: str = "modified"  # added | modified | deleted | renamed
    binary: bool = False
    hunks: List[Hunk] = field(default_factory=list)

    @property
    def added(self) -> List[DiffLine]:
        return [
            line for hunk in self.hunks for line in hunk.lines if line.kind == "add"
        ]

    @property
    def removed(self) -> List[DiffLine]:
        return [
            line for hunk in self.hunks for line in hunk.lines if line.kind == "remove"
        ]

    @property
    def added_source(self) -> str:
        """Just the added lines — what the PR is actually introducing."""
        return "\n".join(line.text for line in self.added)

    @property
    def removed_source(self) -> str:
        return "\n".join(line.text for line in self.removed)

    @property
    def patch_source(self) -> str:
        """Added lines plus their surrounding context, for detectors that need it."""
        return "\n".join(
            line.text
            for hunk in self.hunks
            for line in hunk.lines
            if line.kind in ("add", "context")
        )

    @property
    def changed_lines(self) -> Set[int]:
        return {line.new_lineno for line in self.added if line.new_lineno}

    def first_changed_line(self) -> int:
        lines = sorted(self.changed_lines)
        if lines:
            return lines[0]
        return self.hunks[0].new_start if self.hunks else 1

    def anchor_for(self, needle: str) -> int:
        """Best line number for a finding, by matching a snippet of its code."""
        probe = (needle or "").strip()
        if probe:
            probe = probe.splitlines()[0].strip()
        if probe and len(probe) > 3:
            for line in self.added:
                if probe in line.text and line.new_lineno:
                    return line.new_lineno
        return self.first_changed_line()

    @property
    def extension(self) -> str:
        return os.path.splitext(self.path)[1].lower()


_DIFF_GIT_RE = re.compile(r"^diff --git a/(?P<old>.+?) b/(?P<new>.+)$")
_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<heading>.*)$"
)


def parse_unified_diff(diff: str) -> List[FileDiff]:
    """Parse a unified diff into per-file changes with real line numbers.

    Tolerant by design: a truncated or slightly malformed patch yields the
    files it could read rather than raising, because a review that covers
    most of a PR beats no review at all.
    """
    if not diff:
        return []
    if len(diff) > _MAX_DIFF_BYTES:
        logger.warning("Diff exceeds %d bytes; truncating", _MAX_DIFF_BYTES)
        diff = diff[:_MAX_DIFF_BYTES]

    files: List[FileDiff] = []
    current: Optional[FileDiff] = None
    hunk: Optional[Hunk] = None
    old_lineno = new_lineno = 0

    for raw_line in diff.splitlines():
        header = _DIFF_GIT_RE.match(raw_line)
        if header:
            current = FileDiff(path=header.group("new"), old_path=header.group("old"))
            if current.path != current.old_path:
                current.status = "renamed"
            files.append(current)
            hunk = None
            continue

        if current is None:
            # Some tools emit a bare `--- / +++` patch with no `diff --git`.
            if raw_line.startswith("--- "):
                current = FileDiff(path="", old_path=_strip_diff_path(raw_line[4:]))
                files.append(current)
            continue

        if raw_line.startswith("new file mode"):
            current.status = "added"
            continue
        if raw_line.startswith("deleted file mode"):
            current.status = "deleted"
            continue
        if raw_line.startswith("rename to "):
            current.path = raw_line[len("rename to ") :].strip()
            current.status = "renamed"
            continue
        if raw_line.startswith("Binary files") or raw_line.startswith(
            "GIT binary patch"
        ):
            current.binary = True
            continue
        if raw_line.startswith("--- "):
            current.old_path = _strip_diff_path(raw_line[4:]) or current.old_path
            continue
        if raw_line.startswith("+++ "):
            path = _strip_diff_path(raw_line[4:])
            if path:
                current.path = path
            continue

        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            hunk = Hunk(
                old_start=int(hunk_match.group("old_start")),
                old_count=int(hunk_match.group("old_count") or 1),
                new_start=int(hunk_match.group("new_start")),
                new_count=int(hunk_match.group("new_count") or 1),
                heading=hunk_match.group("heading").strip(),
            )
            current.hunks.append(hunk)
            old_lineno = hunk.old_start
            new_lineno = hunk.new_start
            continue

        if hunk is None:
            continue

        if raw_line.startswith("+"):
            hunk.lines.append(
                DiffLine(kind="add", text=raw_line[1:], new_lineno=new_lineno)
            )
            new_lineno += 1
        elif raw_line.startswith("-"):
            hunk.lines.append(
                DiffLine(kind="remove", text=raw_line[1:], old_lineno=old_lineno)
            )
            old_lineno += 1
        elif raw_line.startswith(" ") or raw_line == "":
            hunk.lines.append(
                DiffLine(
                    kind="context",
                    text=raw_line[1:] if raw_line else "",
                    new_lineno=new_lineno,
                    old_lineno=old_lineno,
                )
            )
            new_lineno += 1
            old_lineno += 1
        # `\ No newline at end of file` and anything else is ignored.

    return [item for item in files if item.path]


def _strip_diff_path(value: str) -> str:
    path = value.strip().split("\t")[0].strip()
    if path == "/dev/null":
        return ""
    for prefix in ("a/", "b/", "i/", "w/", "c/", "o/"):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def diff_from_git(repo_path: str, base: str = "HEAD~1", head: str = "HEAD") -> str:
    """Produce a unified diff between two revisions via ``git diff``."""
    try:
        completed = subprocess.run(
            ["git", "diff", "--no-color", "--find-renames", f"{base}...{head}"],
            cwd=os.path.expanduser(repo_path),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"git diff failed: {exc}") from exc
    if completed.returncode != 0:
        # `a...b` needs a merge base; fall back to the two-dot form.
        completed = subprocess.run(
            ["git", "diff", "--no-color", "--find-renames", base, head],
            cwd=os.path.expanduser(repo_path),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git diff failed")
    return completed.stdout


# ── Findings ──────────────────────────────────────────────────────────────────


@dataclass
class ReviewFinding:
    """One inline review comment, anchored to a file and line."""

    file: str
    line: int
    severity: str  # P0 | P1 | P2
    comment_type: str  # logic | syntax | style
    title: str
    body: str = ""
    suggestion: str = ""
    confidence: float = 0.6
    reviewer: str = ""
    evidence: List[str] = field(default_factory=list)
    rule_id: Optional[str] = None
    category: str = ""

    def key(self) -> Tuple[str, int, str]:
        """Dedupe key — the same issue found twice is still one comment."""
        return (self.file, self.line, self.title.strip().lower())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "severity_label": SEVERITY_LABELS.get(self.severity, self.severity),
            "comment_type": self.comment_type,
            "title": self.title,
            "body": self.body,
            "suggestion": self.suggestion,
            "confidence": round(self.confidence, 2),
            "reviewer": self.reviewer,
            "evidence": list(self.evidence),
            "rule_id": self.rule_id,
            "category": self.category,
        }


def _badge_for(severity: Any) -> str:
    """Normalise any severity spelling onto a P0/P1/P2 badge."""
    text = str(severity or "MEDIUM").strip().upper()
    if text in _SEVERITY_RANK:
        return text
    return _DETECTOR_SEVERITY_TO_BADGE.get(text, "P2")


def _passes_strictness(finding: ReviewFinding, strictness: int) -> bool:
    gate = _STRICTNESS_GATES.get(strictness, _STRICTNESS_GATES[2])
    threshold = gate.get(finding.severity)
    if threshold is None:
        return False  # this badge is not surfaced at this strictness at all
    return finding.confidence >= threshold


# ── Review context ────────────────────────────────────────────────────────────


@dataclass
class ReviewContext:
    """Everything the swarm needs to review one pull request."""

    repo_path: str
    files: List[FileDiff]
    config: ReviewConfig
    graph: Any = None  # CodebaseGraph | None
    pull_request: Dict[str, Any] = field(default_factory=dict)
    _file_cache: Dict[str, Optional[str]] = field(default_factory=dict, repr=False)

    def read_file(self, relative_path: str) -> Optional[str]:
        """Read a file from the working tree, cached; ``None`` when unavailable."""
        if relative_path in self._file_cache:
            return self._file_cache[relative_path]
        content: Optional[str] = None
        candidate = os.path.join(self.repo_path, relative_path)
        try:
            if (
                os.path.isfile(candidate)
                and os.path.getsize(candidate) <= _MAX_FILE_BYTES
            ):
                with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                    content = handle.read()
        except OSError as exc:
            logger.debug("Could not read %s: %s", relative_path, exc)
        self._file_cache[relative_path] = content
        return content

    def config_for(self, path: str) -> ReviewConfig:
        return self.config.for_path(path)


# ── Language routing ──────────────────────────────────────────────────────────

_JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_PY_EXTS = {".py"}
_CODE_EXTS = (
    _JS_EXTS
    | _PY_EXTS
    | {
        ".go",
        ".rb",
        ".rs",
        ".java",
        ".kt",
        ".swift",
        ".php",
        ".cs",
        ".lua",
        ".sql",
    }
)

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|e2e)(/|$)|\.(test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$",
    re.IGNORECASE,
)

_MANIFEST_NAMES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

_GENERATED_HINTS = (
    "@generated",
    "auto-generated",
    "do not edit",
    "code generated by",
)


def _is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path))


def _is_code_file(file_diff: FileDiff) -> bool:
    return file_diff.extension in _CODE_EXTS


def _looks_generated(file_diff: FileDiff) -> bool:
    head = file_diff.added_source[:2000].lower()
    return any(hint in head for hint in _GENERATED_HINTS)


def _reviewable(file_diff: FileDiff, config: ReviewConfig) -> bool:
    """Files worth spending swarm budget on."""
    if file_diff.binary or file_diff.status == "deleted":
        return False
    if config.is_ignored(file_diff.path):
        return False
    if not file_diff.added:
        return False
    return True


# ── Detector plumbing ─────────────────────────────────────────────────────────

_DETECTOR_CACHE: Dict[str, Any] = {}


def _detector(agent_name: str) -> Optional[Any]:
    """Instantiate one of this toolkit's detector agents, once, keylessly."""
    if agent_name in _DETECTOR_CACHE:
        return _DETECTOR_CACHE[agent_name]
    try:
        from agents.cli import AGENTS

        agent_class = AGENTS.get(agent_name)
        instance = agent_class() if agent_class else None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Detector %s unavailable: %s", agent_name, exc)
        instance = None
    _DETECTOR_CACHE[agent_name] = instance
    return instance


def _run_detector(agent_name: str, tool: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Call one detector tool and normalise whatever shape it returns.

    Detectors are independent and occasionally raise on odd input; one
    failing reviewer must never take the whole review down with it.
    """
    agent = _detector(agent_name)
    if agent is None:
        return []
    handler = agent._bind_tool_handlers().get(tool)
    if handler is None:
        return []
    try:
        result = handler(**kwargs)
    except Exception as exc:
        logger.debug("Detector %s.%s failed: %s", agent_name, tool, exc)
        return []
    return _normalize_detector_output(result)


def _normalize_detector_output(result: Any) -> List[Dict[str, Any]]:
    if isinstance(result, dict):
        for key in ("findings", "issues", "vulnerabilities", "results"):
            value = result.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    return []


def _finding_text(raw: Dict[str, Any]) -> str:
    for key in ("issue", "title", "message", "description", "finding", "problem"):
        value = raw.get(key)
        if value:
            return str(value)
    return "Issue detected"


def _finding_fix(raw: Dict[str, Any]) -> str:
    for key in ("fix", "recommendation", "remediation", "suggestion", "action"):
        value = raw.get(key)
        if value:
            return str(value)
    return ""


def _finding_evidence(raw: Dict[str, Any]) -> List[str]:
    evidence: List[str] = []
    for key in ("evidence", "snippet", "code", "match", "detail", "context"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            evidence.append(value.strip()[:400])
        elif isinstance(value, list):
            evidence.extend(str(item)[:400] for item in value[:3] if item)
    return evidence[:3]


def _classify_comment_type(badge: str, text: str) -> str:
    """Sort a finding into the logic / syntax / style buckets."""
    lowered = text.lower()
    if re.search(
        r"syntax error|won'?t compile|unparseable|merge conflict marker|"
        r"undefined (?:name|variable|method)|missing import|unresolved import",
        lowered,
    ):
        return "syntax"
    if badge in ("P0", "P1"):
        return "logic"
    if re.search(
        r"naming|format|readab|style|convention|comment|docstring|lint|"
        r"magic number|duplicat|dead code|unused",
        lowered,
    ):
        return "style"
    return "style" if badge == "P2" else "logic"


def _findings_from_detector(
    raws: Sequence[Dict[str, Any]],
    file_diff: FileDiff,
    reviewer: str,
    category: str,
    base_confidence: float = 0.65,
    force_type: Optional[str] = None,
) -> List[ReviewFinding]:
    findings: List[ReviewFinding] = []
    for raw in raws:
        text = _finding_text(raw)
        badge = _badge_for(raw.get("severity"))
        evidence = _finding_evidence(raw)
        anchor_probe = str(
            raw.get("snippet") or raw.get("code") or raw.get("match") or text
        )
        confidence = raw.get("confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = base_confidence
        findings.append(
            ReviewFinding(
                file=file_diff.path,
                line=file_diff.anchor_for(anchor_probe),
                severity=badge,
                comment_type=force_type or _classify_comment_type(badge, text),
                title=text,
                body=_finding_fix(raw),
                suggestion=str(raw.get("suggested_code") or ""),
                confidence=confidence,
                reviewer=reviewer,
                evidence=evidence,
                category=str(raw.get("category") or category),
            )
        )
    return findings


# ── Symbol analysis ───────────────────────────────────────────────────────────

_DEF_PATTERNS = (
    re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)"),
    re.compile(r"^\s*class\s+(?P<name>\w+)\b"),
    re.compile(
        r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
        r"(?P<name>\w+)\s*\((?P<params>[^)]*)\)"
    ),
    re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*(?::[^=]+)?=\s*"
        r"(?:async\s*)?\((?P<params>[^)]*)\)\s*(?::[^=]*?)?=>"
    ),
    re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+(?P<name>\w+)\b"),
    re.compile(r"^\s*(?:export\s+)?func\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)"),
)


def _definitions_in(lines: Iterable[str]) -> Dict[str, str]:
    """Map symbol name to its raw parameter list, for the definitions in ``lines``."""
    found: Dict[str, str] = {}
    for text in lines:
        for pattern in _DEF_PATTERNS:
            match = pattern.match(text)
            if match:
                found[match.group("name")] = (
                    match.groupdict().get("params") or ""
                ).strip()
                break
    return found


def _required_params(params: str) -> List[str]:
    """Parameter names that a caller must supply, ignoring defaults and self."""
    required: List[str] = []
    depth = 0
    current = ""
    for char in params:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            required.append(current)
            current = ""
        else:
            current += char
    required.append(current)

    names: List[str] = []
    for chunk in required:
        chunk = chunk.strip()
        if not chunk or chunk in ("self", "cls") or chunk.startswith(("*", "...")):
            continue
        if "=" in chunk:
            continue  # has a default — existing callers stay valid
        name = chunk.split(":")[0].strip()
        if name.endswith("?"):
            continue  # TypeScript optional parameter
        if name:
            names.append(name)
    return names


@dataclass
class SymbolChange:
    """A function or class whose definition the diff touched."""

    name: str
    file: str
    kind: str  # added | removed | signature_changed | modified
    old_params: str = ""
    new_params: str = ""


def symbol_changes(file_diff: FileDiff) -> List[SymbolChange]:
    """Work out which symbols the diff added, removed, or re-signed."""
    added = _definitions_in(line.text for line in file_diff.added)
    removed = _definitions_in(line.text for line in file_diff.removed)
    changes: List[SymbolChange] = []
    for name, params in added.items():
        if name in removed:
            if _required_params(params) != _required_params(removed[name]):
                changes.append(
                    SymbolChange(
                        name=name,
                        file=file_diff.path,
                        kind="signature_changed",
                        old_params=removed[name],
                        new_params=params,
                    )
                )
            else:
                changes.append(
                    SymbolChange(name=name, file=file_diff.path, kind="modified")
                )
        else:
            changes.append(
                SymbolChange(
                    name=name, file=file_diff.path, kind="added", new_params=params
                )
            )
    for name, params in removed.items():
        if name not in added:
            changes.append(
                SymbolChange(
                    name=name, file=file_diff.path, kind="removed", old_params=params
                )
            )
    return changes


# ── The swarm ─────────────────────────────────────────────────────────────────


# ── Injected SQL ──────────────────────────────────────────────────────────────

#: A real SQL statement shape, not the English words "select" or "update".
_SQL_STATEMENT_RE = re.compile(
    r"(?:SELECT\b.{0,200}?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\S+\s+SET\b"
    r"|DELETE\s+FROM\b)",
    re.IGNORECASE,
)

#: A value spliced into that statement rather than bound to it.
_SQL_INTERPOLATION_RE = re.compile(
    # The `%` case must follow a closing quote: `"... %s" % value` splices,
    # while `"... %s", (value,)` is the bound-parameter form and is safe.
    r"""(?:f["'`][^\n]*\{|\$\{|["']\s*\+\s*\w|\.format\s*\(|["']\s*%\s*[(\w])"""
)

_SQL_CALL_RE = re.compile(
    r"\b(?:execute|executemany|query|raw|prepare)\s*\(", re.IGNORECASE
)

_SQL_EXEMPT_RE = re.compile(r"#\s*nosec|nosec|eslint-disable.*sql", re.IGNORECASE)


def _injected_sql(file_diff: FileDiff) -> List[ReviewFinding]:
    """Flag SQL built by concatenation or interpolation on an added line.

    Unconditional by design. Every other convention check asks "does the rest
    of this repo do it the safe way?" before speaking up; injection does not
    get that courtesy, because the answer does not change whether the query is
    exploitable.
    """
    findings: List[ReviewFinding] = []
    for line in file_diff.added:
        text = line.text
        if not _SQL_CALL_RE.search(text):
            continue
        if not (_SQL_STATEMENT_RE.search(text) and _SQL_INTERPOLATION_RE.search(text)):
            continue
        if _SQL_EXEMPT_RE.search(text):
            continue
        findings.append(
            ReviewFinding(
                file=file_diff.path,
                line=line.new_lineno or file_diff.first_changed_line(),
                severity="P0",
                comment_type="logic",
                title="SQL query built by string interpolation — injection risk",
                body=(
                    "This query splices a value into the SQL text instead of binding "
                    "it. If any part of that value reaches the request, it is a SQL "
                    "injection. Pass the value as a bound parameter instead."
                ),
                confidence=0.85,
                reviewer="security",
                evidence=[f"`{text.strip()[:140]}`"],
                category="sql_injection",
            )
        )
    return findings


def review_security(context: ReviewContext) -> List[ReviewFinding]:
    """Security reviewer — injection, secrets, auth, upload, and transport risk."""
    findings: List[ReviewFinding] = []
    checks = (
        "audit_sql_injection",
        "audit_xss_patterns",
        "audit_hardcoded_secrets",
        "audit_input_validation",
        "audit_file_upload",
        "audit_csrf_protection",
        "audit_websocket_auth",
        "audit_error_handling",
    )
    for file_diff in context.files:
        if not _reviewable(file_diff, context.config) or not _is_code_file(file_diff):
            continue
        source = file_diff.patch_source
        if not source.strip():
            continue
        spliced_sql = _injected_sql(file_diff)
        findings.extend(spliced_sql)
        for check in checks:
            # The shared detector reaches further than `_injected_sql` — it
            # catches a query built into a variable and executed on another
            # line — but on a query this reviewer already flagged it only
            # restates it, at a lower severity and a worse anchor.
            if check == "audit_sql_injection" and spliced_sql:
                continue
            raws = _run_detector("security_audit", check, code=source)
            findings.extend(
                _findings_from_detector(
                    raws,
                    file_diff,
                    reviewer="security",
                    category=check.replace("audit_", ""),
                    base_confidence=0.75,
                    force_type="logic",
                )
            )
        if re.search(r"\bjwt\b|jsonwebtoken|PyJWT", source, re.IGNORECASE):
            findings.extend(
                _findings_from_detector(
                    _run_detector(
                        "security_audit", "check_jwt_implementation", code=source
                    ),
                    file_diff,
                    reviewer="security",
                    category="jwt",
                    base_confidence=0.75,
                    force_type="logic",
                )
            )
        if re.search(
            r"\boauth\b|apple|google|refresh[_ ]?token", source, re.IGNORECASE
        ):
            for tool in ("review_refresh_token_rotation", "review_oauth_flow"):
                findings.extend(
                    _findings_from_detector(
                        _run_detector("auth_security", tool, code=source),
                        file_diff,
                        reviewer="security",
                        category="auth",
                        base_confidence=0.7,
                        force_type="logic",
                    )
                )
    return findings


def review_logic(context: ReviewContext) -> List[ReviewFinding]:
    """Logic reviewer — control flow, state machines, idempotency, async hazards."""
    findings: List[ReviewFinding] = []
    for file_diff in context.files:
        if not _reviewable(file_diff, context.config) or not _is_code_file(file_diff):
            continue
        source = file_diff.patch_source
        if not source.strip():
            continue

        findings.extend(
            _findings_from_detector(
                _run_detector("flow_audit", "audit_flow_logic", code=source),
                file_diff,
                reviewer="logic",
                category="flow",
                base_confidence=0.7,
                force_type="logic",
            )
        )

        if file_diff.extension in _JS_EXTS:
            if re.search(r"\b(?:router|app)\.(?:get|post|put|patch|delete)\b", source):
                for agent_name, tool in (
                    ("code_review", "review_express_route"),
                    ("api_architect", "review_error_response_shape"),
                    ("api_architect", "audit_status_codes"),
                    ("api_architect", "review_pagination"),
                ):
                    findings.extend(
                        _findings_from_detector(
                            _run_detector(agent_name, tool, code=source),
                            file_diff,
                            reviewer="logic",
                            category="api",
                            base_confidence=0.6,
                        )
                    )
            if re.search(r"\buse(?:State|Effect|Memo|Callback)\b|<[A-Z]\w*", source):
                findings.extend(
                    _findings_from_detector(
                        _run_detector(
                            "code_review",
                            "review_react_component",
                            code=source,
                            is_native=file_diff.path.lower().find("native") >= 0,
                        ),
                        file_diff,
                        reviewer="logic",
                        category="react",
                        base_confidence=0.55,
                    )
                )
            # Require actual webhook shape. Matching a bare "stripe" ran the
            # webhook reviewer over any route that merely read STRIPE_KEY, and
            # reported missing signature verification on a plain POST handler.
            if re.search(
                r"constructEvent|stripe[-_]?signature|\bwebhooks?\b",
                source,
                re.IGNORECASE,
            ):
                findings.extend(
                    _findings_from_detector(
                        _run_detector(
                            "code_review", "review_stripe_webhook", code=source
                        ),
                        file_diff,
                        reviewer="logic",
                        category="billing",
                        base_confidence=0.7,
                        force_type="logic",
                    )
                )

        if re.search(
            r"\b(?:pgTable|sqliteTable|CREATE TABLE|Column\()", source, re.IGNORECASE
        ):
            for tool in ("review_index_coverage", "review_constraints"):
                findings.extend(
                    _findings_from_detector(
                        _run_detector("database_architect", tool, schema_code=source),
                        file_diff,
                        reviewer="logic",
                        category="schema",
                        base_confidence=0.65,
                    )
                )
        if re.search(
            r"\b(?:migrat|alembic|ALTER TABLE)\b",
            file_diff.path + source,
            re.IGNORECASE,
        ):
            findings.extend(
                _findings_from_detector(
                    _run_detector(
                        "database_architect",
                        "review_migration_safety",
                        migration_code=source,
                    ),
                    file_diff,
                    reviewer="logic",
                    category="migration",
                    base_confidence=0.7,
                    force_type="logic",
                )
            )
        findings.extend(
            _findings_from_detector(
                _run_detector("database_architect", "review_n_plus_one", code=source),
                file_diff,
                reviewer="logic",
                category="query",
                base_confidence=0.6,
            )
        )
    return findings


def review_performance(context: ReviewContext) -> List[ReviewFinding]:
    """Performance reviewer — bundle weight, render cost, layout shift."""
    findings: List[ReviewFinding] = []
    for file_diff in context.files:
        if not _reviewable(file_diff, context.config):
            continue
        if file_diff.extension not in _JS_EXTS:
            continue
        source = file_diff.patch_source
        if not source.strip():
            continue
        findings.extend(
            _findings_from_detector(
                _run_detector(
                    "frontend_performance", "audit_frontend_performance", code=source
                ),
                file_diff,
                reviewer="performance",
                category="performance",
                base_confidence=0.55,
            )
        )
    return findings


def review_dependencies(context: ReviewContext) -> List[ReviewFinding]:
    """Supply-chain reviewer — manifests and lockfiles the PR touches."""
    findings: List[ReviewFinding] = []
    for file_diff in context.files:
        if file_diff.binary or file_diff.status == "deleted":
            continue
        if os.path.basename(file_diff.path) not in _MANIFEST_NAMES:
            continue
        content = context.read_file(file_diff.path) or file_diff.patch_source
        if not content.strip():
            continue
        findings.extend(
            _findings_from_detector(
                _run_detector(
                    "supply_chain_audit",
                    "audit_supply_chain",
                    content=content,
                    path=file_diff.path,
                ),
                file_diff,
                reviewer="dependencies",
                category="supply_chain",
                base_confidence=0.8,
                force_type="logic",
            )
        )
    return findings


def review_impact(context: ReviewContext) -> List[ReviewFinding]:
    """Cross-file impact reviewer — the blast radius a diff-only tool cannot see.

    Queries the codebase graph for everything that calls or imports what the
    PR changed, and flags the callers this PR leaves behind.
    """
    findings: List[ReviewFinding] = []
    graph = context.graph
    if graph is None:
        return findings

    changed_paths = {file_diff.path for file_diff in context.files}

    for file_diff in context.files:
        if file_diff.binary or not _is_code_file(file_diff):
            continue
        if context.config.is_ignored(file_diff.path):
            continue

        for change in symbol_changes(file_diff):
            if change.kind not in ("signature_changed", "removed"):
                continue
            try:
                callers = graph.find_callers(change.name)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Graph lookup failed for %s: %s", change.name, exc)
                continue

            outside = [
                caller
                for caller in callers
                if _relative(caller.get("file", ""), context.repo_path)
                not in changed_paths
            ]
            if not outside:
                continue

            sites = _format_call_sites(outside, context.repo_path)
            if change.kind == "signature_changed":
                added_params = [
                    name
                    for name in _required_params(change.new_params)
                    if name not in _required_params(change.old_params)
                ]
                detail = (
                    f"now requires `{', '.join(added_params)}`"
                    if added_params
                    else "changed its required parameters"
                )
                findings.append(
                    ReviewFinding(
                        file=file_diff.path,
                        line=file_diff.anchor_for(change.name),
                        severity="P0" if added_params else "P1",
                        comment_type="logic",
                        title=(
                            f"`{change.name}` {detail}, but "
                            f"{len(outside)} call site(s) outside this PR were not updated"
                        ),
                        body=(
                            f"Signature changed from `({change.old_params})` to "
                            f"`({change.new_params})`. Update the call sites below, or give the "
                            "new parameter a default so existing callers keep working."
                        ),
                        confidence=0.85 if added_params else 0.6,
                        reviewer="impact",
                        evidence=sites,
                        category="breaking_change",
                    )
                )
            else:
                findings.append(
                    ReviewFinding(
                        file=file_diff.path,
                        line=file_diff.first_changed_line(),
                        severity="P0",
                        comment_type="logic",
                        title=(
                            f"`{change.name}` was removed but is still called from "
                            f"{len(outside)} site(s) outside this PR"
                        ),
                        body=(
                            "Removing this definition breaks its remaining callers. "
                            "Either keep a shim, or update every call site in this PR."
                        ),
                        confidence=0.8,
                        reviewer="impact",
                        evidence=sites,
                        category="breaking_change",
                    )
                )

        # A module this PR stops exporting, that other files still import.
        for removed_import in _removed_exports(file_diff):
            try:
                importers = graph.find_importers(removed_import)
            except Exception:  # pragma: no cover - defensive
                continue
            outside = [
                item
                for item in importers
                if _relative(item.get("file", ""), context.repo_path)
                not in changed_paths
            ]
            if outside:
                findings.append(
                    ReviewFinding(
                        file=file_diff.path,
                        line=file_diff.first_changed_line(),
                        severity="P1",
                        comment_type="logic",
                        title=(
                            f"Export `{removed_import}` removed while "
                            f"{len(outside)} file(s) still import it"
                        ),
                        body="Keep the export, or update the importing modules in this PR.",
                        confidence=0.7,
                        reviewer="impact",
                        evidence=_format_call_sites(outside, context.repo_path),
                        category="breaking_change",
                    )
                )
    return findings


def _relative(path: str, repo_path: str) -> str:
    if not path:
        return ""
    try:
        return os.path.relpath(path, repo_path).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")


def _format_call_sites(rows: Sequence[Dict[str, Any]], repo_path: str) -> List[str]:
    sites: List[str] = []
    for row in rows[:5]:
        path = _relative(str(row.get("file", "")), repo_path)
        line = row.get("line")
        caller = row.get("caller_func") or row.get("caller") or ""
        location = f"{path}:{line}" if line else path
        sites.append(f"{location}{f' in `{caller}`' if caller else ''}")
    if len(rows) > 5:
        sites.append(f"…and {len(rows) - 5} more")
    return sites


_EXPORT_RE = re.compile(
    r"^\s*(?:export\s+(?:const|function|class|default|let|var)\s+(?P<js>\w+)"
    r"|__all__\s*=|module\.exports)"
)


def _removed_exports(file_diff: FileDiff) -> List[str]:
    """Names this diff stops exporting."""
    removed = {
        match.group("js")
        for match in (_EXPORT_RE.match(line.text) for line in file_diff.removed)
        if match and match.group("js")
    }
    still_exported = {
        match.group("js")
        for match in (_EXPORT_RE.match(line.text) for line in file_diff.added)
        if match and match.group("js")
    }
    return sorted(removed - still_exported)


# ── Convention drift ──────────────────────────────────────────────────────────


@dataclass
class ConventionProbe:
    """One "the codebase does X, this diff doesn't" comparison."""

    name: str
    title: str
    body: str
    violation: str  # regex matched against added lines
    convention: str  # regex whose presence elsewhere proves the convention
    requires: Tuple[str, ...] = ()  # further patterns the same line must match
    exempt: str = ""  # regex that, if present in the diff, clears the finding
    severity: str = "P1"
    comment_type: str = "logic"
    extensions: Tuple[str, ...] = ()


_CONVENTION_PROBES: Tuple[ConventionProbe, ...] = (
    ConventionProbe(
        name="print_debug",
        title="`print()` here, structured logger everywhere else",
        body=(
            "This codebase logs through a structured logger. A bare `print` "
            "bypasses log levels and tends to survive into production."
        ),
        violation=r"^\s*print\s*\(",
        convention=r"\b(?:logger|logging)\.(?:info|warning|error|debug)\s*\(",
        exempt=r"^\s*#|argparse|__main__",
        severity="P2",
        comment_type="style",
        extensions=(".py",),
    ),
    ConventionProbe(
        name="console_log",
        title="`console.log` here, structured logger everywhere else",
        body=(
            "This codebase logs through a structured logger. A bare "
            "`console.log` bypasses log levels and redaction, and tends to "
            "leak into production output."
        ),
        violation=r"^\s*console\.(?:log|debug|info)\s*\(",
        convention=r"\b(?:logger|log)\.(?:info|warn|error|debug)\s*\(|\bpino\b|\bwinston\b",
        severity="P2",
        comment_type="style",
        extensions=tuple(_JS_EXTS),
    ),
    ConventionProbe(
        name="direct_env",
        title="Reads `process.env` directly, bypassing the config module",
        body=(
            "The codebase centralises environment access so values are "
            "validated once at boot. Reading `process.env` inline skips that "
            "validation and fails at request time instead of start-up."
        ),
        violation=r"process\.env\.[A-Z_]+",
        convention=r"from\s+['\"][^'\"]*config['\"]|require\(['\"][^'\"]*config['\"]\)",
        exempt=r"^\s*(?://|/\*)|NODE_ENV",
        severity="P2",
        comment_type="style",
        extensions=tuple(_JS_EXTS),
    ),
    ConventionProbe(
        name="unvalidated_body",
        title="Reads `req.body` without the schema validation used elsewhere",
        body=(
            "Sibling handlers validate their request body against a schema "
            "before use. Trusting `req.body` here lets malformed input reach "
            "the database layer."
        ),
        violation=r"req\.body\b",
        convention=r"\b(?:z|Joi|yup)\.object\s*\(|\.safeParse\s*\(|\bvalidateRequest\b",
        exempt=r"\.(?:safeParse|parse)\s*\(|\bvalidate\w*\s*\(",
        severity="P1",
        extensions=tuple(_JS_EXTS),
    ),
)


def review_conventions(context: ReviewContext) -> List[ReviewFinding]:
    """Convention reviewer — flags drift from what the rest of the repo does.

    Each probe only fires when the surrounding codebase demonstrably follows
    the convention being broken, so a repo that never adopted a pattern is
    never nagged about it.
    """
    findings: List[ReviewFinding] = []
    corpus = _repo_corpus(context)
    if not corpus:
        return findings

    for file_diff in context.files:
        if not _reviewable(file_diff, context.config) or not _is_code_file(file_diff):
            continue
        if _is_test_path(file_diff.path) or _looks_generated(file_diff):
            continue
        for probe in _CONVENTION_PROBES:
            if probe.extensions and file_diff.extension not in probe.extensions:
                continue
            offenders = [
                line
                for line in file_diff.added
                if re.search(probe.violation, line.text, re.IGNORECASE)
                and all(
                    re.search(extra, line.text, re.IGNORECASE)
                    for extra in probe.requires
                )
            ]
            if not offenders:
                continue
            if probe.exempt and re.search(
                probe.exempt, file_diff.patch_source, re.IGNORECASE | re.MULTILINE
            ):
                continue
            support = corpus.count_matches(probe.convention, exclude=file_diff.path)
            # The file's own untouched code is the strongest evidence there is:
            # a new helper ignoring the pattern the function above it follows is
            # drift you can point at directly, so it counts double. Evidence from
            # elsewhere still needs two files before this reviewer speaks up.
            in_file = _self_follows_convention(context, file_diff, probe.convention)
            support += 2 if in_file else 0
            if support < 2:
                continue  # not an established convention — stay quiet
            offender = offenders[0]
            findings.append(
                ReviewFinding(
                    file=file_diff.path,
                    line=offender.new_lineno or file_diff.first_changed_line(),
                    severity=probe.severity,
                    comment_type=probe.comment_type,
                    title=probe.title,
                    body=probe.body,
                    confidence=min(0.9, 0.5 + 0.05 * support),
                    reviewer="conventions",
                    evidence=[
                        f"`{offender.text.strip()[:120]}`",
                        (
                            "the rest of this file already follows the pattern"
                            if in_file
                            else f"{support} file(s) elsewhere follow the established pattern"
                        ),
                    ],
                    category=f"convention:{probe.name}",
                )
            )
    return findings


def _self_follows_convention(
    context: ReviewContext, file_diff: FileDiff, pattern: str
) -> bool:
    """True when the changed file already follows ``pattern`` outside the diff."""
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:  # pragma: no cover - defensive
        return False
    # Prefer the diff's own context and removed lines — they are the pre-change
    # state by definition, with no dependence on the working tree.
    unchanged = "\n".join(
        line.text
        for hunk in file_diff.hunks
        for line in hunk.lines
        if line.kind in ("context", "remove")
    )
    if compiled.search(unchanged):
        return True
    content = context.read_file(file_diff.path)
    if not content:
        return False
    added = {line.text for line in file_diff.added}
    remainder = "\n".join(line for line in content.splitlines() if line not in added)
    return bool(compiled.search(remainder))


class _RepoCorpus:
    """A bounded sample of repository source, for convention comparisons."""

    _MAX_FILES = 400
    _MAX_BYTES_PER_FILE = 200_000

    def __init__(self, files: Dict[str, str]) -> None:
        self._files = files

    def count_matches(self, pattern: str, exclude: str = "") -> int:
        """Number of other files where ``pattern`` appears."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:  # pragma: no cover - defensive
            return 0
        return sum(
            1
            for path, content in self._files.items()
            if path != exclude and compiled.search(content)
        )

    def __bool__(self) -> bool:
        return bool(self._files)


_CORPUS_CACHE: Dict[str, _RepoCorpus] = {}


def _repo_corpus(context: ReviewContext) -> _RepoCorpus:
    """Sample the repo's source files once per review, and cache it."""
    root = os.path.realpath(context.repo_path)
    cached = _CORPUS_CACHE.get(root)
    if cached is not None:
        return cached

    from agents.review_config import _SKIP_SCAN_DIRS

    collected: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_SCAN_DIRS]
        for filename in filenames:
            if os.path.splitext(filename)[1].lower() not in _CODE_EXTS:
                continue
            full = os.path.join(dirpath, filename)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            if _is_test_path(relative):
                continue
            try:
                if os.path.getsize(full) > _RepoCorpus._MAX_BYTES_PER_FILE:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    collected[relative] = handle.read()
            except OSError:
                continue
            if len(collected) >= _RepoCorpus._MAX_FILES:
                break
        if len(collected) >= _RepoCorpus._MAX_FILES:
            break

    corpus = _RepoCorpus(collected)
    _CORPUS_CACHE[root] = corpus
    return corpus


def clear_caches() -> None:
    """Drop cached corpora and detector instances (used between test runs)."""
    _CORPUS_CACHE.clear()
    _DETECTOR_CACHE.clear()
    _TEST_CORPUS_CACHE.clear()


# ── Custom rules ──────────────────────────────────────────────────────────────

_RULE_SEVERITY_TO_BADGE = {"high": "P0", "medium": "P1", "low": "P2"}

#: Rules phrased as a requirement, mapped to evidence that the requirement is met.
_RULE_EVIDENCE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"rate.?limit", r"rate.?limit|throttle|limiter|slowDown"),
    (
        r"\bauth(?:entication|orization)?\b|authenticated",
        r"auth|requireUser|isAuthenticated|@login_required|verify_token",
    ),
    (r"\bvalidat", r"validat|\.parse\(|safeParse|schema|pydantic|BaseModel"),
    (
        r"error handling|try/catch|handle errors",
        r"try\s*\{|try:|catch\s*\(|except\b|\.catch\(",
    ),
    (r"\blog(?:ging|ged)?\b", r"logger\.|logging\.|log\."),
    (r"\btest(?:s|ed|ing)?\b", r"\btest|describe\(|it\(|assert"),
    (
        r"\btype(?:d|s)?\b|type hint|annotation",
        r":\s*\w+|->\s*\w+|interface\s|\btype\s+\w+\s*=",
    ),
    (r"idempoten", r"idempoten|dedup|event\.id"),
    (r"\btransaction", r"transaction|BEGIN|\.atomic\(|with\s+\w*session"),
    (r"\btimeout", r"timeout|AbortController|deadline"),
)


def review_rules(context: ReviewContext) -> List[ReviewFinding]:
    """Custom-rule reviewer — enforces rules from ``greptile.json`` / ``.greptile/``.

    A rule is reported when the file it scopes to was changed and the diff
    shows no evidence the rule was honoured. Rules whose wording this
    reviewer cannot turn into a deterministic check are still surfaced to
    the LLM pass rather than silently dropped.
    """
    findings: List[ReviewFinding] = []
    for file_diff in context.files:
        if not _reviewable(file_diff, context.config):
            continue
        scoped = context.config_for(file_diff.path)
        source = file_diff.patch_source
        for rule in scoped.rules_for(file_diff.path):
            evidence_pattern = _evidence_pattern_for(rule.rule)
            if evidence_pattern is None:
                continue
            if re.search(evidence_pattern, source, re.IGNORECASE):
                continue
            findings.append(
                ReviewFinding(
                    file=file_diff.path,
                    line=file_diff.first_changed_line(),
                    severity=_RULE_SEVERITY_TO_BADGE.get(rule.severity, "P1"),
                    comment_type="logic",
                    title=f"Repository rule not satisfied: {rule.rule}",
                    body=(
                        "This rule is configured for files matching "
                        f"`{', '.join(rule.scope) or '**'}`, and the change shows no "
                        "sign of meeting it."
                    ),
                    confidence=0.6,
                    reviewer="rules",
                    evidence=[f"rule defined in {rule.source or 'greptile.json'}"],
                    rule_id=rule.id,
                    category="custom_rule",
                )
            )
    return findings


def _evidence_pattern_for(rule_text: str) -> Optional[str]:
    """Find a deterministic signal that a prose rule was honoured."""
    lowered = rule_text.lower()
    for trigger, evidence in _RULE_EVIDENCE_PATTERNS:
        if re.search(trigger, lowered):
            return evidence
    return None


def unenforceable_rules(context: ReviewContext) -> List[Rule]:
    """Configured rules that need a language model to judge."""
    seen: Dict[str, Rule] = {}
    for file_diff in context.files:
        if not _reviewable(file_diff, context.config):
            continue
        for rule in context.config_for(file_diff.path).rules_for(file_diff.path):
            if _evidence_pattern_for(rule.rule) is None:
                seen.setdefault(rule.id or rule.rule, rule)
    return list(seen.values())


# ── Test coverage ─────────────────────────────────────────────────────────────


def review_tests(context: ReviewContext) -> List[ReviewFinding]:
    """Test reviewer — new behaviour that nothing exercises."""
    findings: List[ReviewFinding] = []
    touched_tests = any(_is_test_path(item.path) for item in context.files)
    corpus_tests = _test_corpus(context)

    for file_diff in context.files:
        if not _reviewable(file_diff, context.config) or not _is_code_file(file_diff):
            continue
        if _is_test_path(file_diff.path) or _looks_generated(file_diff):
            continue
        new_symbols = [
            change.name
            for change in symbol_changes(file_diff)
            if change.kind == "added" and not change.name.startswith("_")
        ]
        if not new_symbols:
            continue
        uncovered = [
            name
            for name in new_symbols
            if not any(
                re.search(rf"\b{re.escape(name)}\b", content)
                for content in corpus_tests
            )
        ]
        if not uncovered:
            continue
        findings.append(
            ReviewFinding(
                file=file_diff.path,
                line=file_diff.anchor_for(uncovered[0]),
                severity="P2",
                comment_type="style",
                title=(
                    f"{len(uncovered)} new symbol(s) here have no test referencing them: "
                    + ", ".join(f"`{name}`" for name in uncovered[:4])
                ),
                body=(
                    "No test file in the repository mentions these. "
                    + (
                        "This PR does touch tests — consider extending them to cover the new code."
                        if touched_tests
                        else "Adding coverage now is cheaper than debugging this later."
                    )
                ),
                confidence=0.55,
                reviewer="tests",
                evidence=[f"searched {len(corpus_tests)} test file(s)"],
                category="test_coverage",
            )
        )
    return findings


_TEST_CORPUS_CACHE: Dict[str, List[str]] = {}


def _test_corpus(context: ReviewContext) -> List[str]:
    root = os.path.realpath(context.repo_path)
    cached = _TEST_CORPUS_CACHE.get(root)
    if cached is not None:
        return cached

    from agents.review_config import _SKIP_SCAN_DIRS

    contents: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_SCAN_DIRS]
        for filename in filenames:
            relative = os.path.relpath(os.path.join(dirpath, filename), root).replace(
                os.sep, "/"
            )
            if not _is_test_path(relative):
                continue
            if os.path.splitext(filename)[1].lower() not in _CODE_EXTS:
                continue
            try:
                full = os.path.join(dirpath, filename)
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    contents.append(handle.read())
            except OSError:
                continue
        if len(contents) >= 300:
            break

    _TEST_CORPUS_CACHE[root] = contents
    return contents


#: The swarm. Each member runs in parallel over the same review context.
SWARM: Tuple[Tuple[str, Callable[[ReviewContext], List[ReviewFinding]]], ...] = (
    ("security", review_security),
    ("logic", review_logic),
    ("impact", review_impact),
    ("conventions", review_conventions),
    ("performance", review_performance),
    ("dependencies", review_dependencies),
    ("rules", review_rules),
    ("tests", review_tests),
)


# ── Learning ──────────────────────────────────────────────────────────────────

#: Categories that never get suppressed, however often they are waved through.
#: Convention probes carrying P0 weight are folded in below — a team dismissing
#: "you interpolated into SQL" four times must not train it into silence.
_NEVER_SUPPRESSED = (
    "sql_injection",
    "xss_patterns",
    "hardcoded_secrets",
    "file_upload",
    "csrf_protection",
    "websocket_auth",
    "input_validation",
    "auth",
    "jwt",
    "supply_chain",
    "breaking_change",
) + tuple(
    f"convention:{probe.name}" for probe in _CONVENTION_PROBES if probe.severity == "P0"
)

#: Ignores of the same category before it stops being surfaced.
_SUPPRESSION_THRESHOLD = 3

_MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_feedback (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project    TEXT NOT NULL,
    category   TEXT NOT NULL,
    reviewer   TEXT,
    comment_type TEXT,
    severity   TEXT,
    verdict    TEXT NOT NULL,
    title      TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rf_project ON review_feedback(project, category);
"""

#: Feedback verdicts, and whether each one counts as the team ignoring a comment.
VERDICTS = {
    "upvote": False,
    "addressed": False,
    "downvote": True,
    "ignored": True,
}


class ReviewMemory:
    """Remembers which review comments a team acts on, and which they wave through.

    Mirrors how a reviewer earns its keep over time: 👍/👎 reactions and
    whether a comment was addressed before merge feed a per-category
    tally, and a category the team has ignored repeatedly stops being
    surfaced. Security and breaking-change categories are exempt — those
    stay loud no matter how often they are dismissed.
    """

    def __init__(self, database_path: Optional[str] = None) -> None:
        import sqlite3

        self.path = os.path.expanduser(
            database_path
            or os.getenv("AGENTS_REVIEW_MEMORY")
            or os.path.join("~", ".agents", "review-memory.db")
        )
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        with self.connection:
            self.connection.executescript(_MEMORY_SCHEMA)

    def __enter__(self) -> "ReviewMemory":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.connection.close()
        except Exception:  # pragma: no cover - defensive
            pass

    def record(
        self, project: str, finding: Dict[str, Any], verdict: str
    ) -> Dict[str, Any]:
        """Record one reaction or outcome against a review comment."""
        import datetime

        verdict = str(verdict or "").strip().lower()
        if verdict not in VERDICTS:
            raise ValueError(
                f"verdict must be one of {', '.join(sorted(VERDICTS))}; got '{verdict}'"
            )
        category = str(finding.get("category") or finding.get("reviewer") or "general")
        row = (
            project,
            category,
            str(finding.get("reviewer") or ""),
            str(finding.get("comment_type") or ""),
            str(finding.get("severity") or ""),
            verdict,
            str(finding.get("title") or "")[:400],
            datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        )
        with self.connection:
            self.connection.execute(
                "INSERT INTO review_feedback"
                "(project, category, reviewer, comment_type, severity, verdict, title, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
        return {"project": project, "category": category, "verdict": verdict}

    def tallies(self, project: str) -> Dict[str, Dict[str, int]]:
        rows = self.connection.execute(
            "SELECT category, verdict, COUNT(*) AS n FROM review_feedback"
            " WHERE project = ? GROUP BY category, verdict",
            (project,),
        ).fetchall()
        tallies: Dict[str, Dict[str, int]] = {}
        for row in rows:
            bucket = tallies.setdefault(
                row["category"], {"kept": 0, "ignored": 0, "total": 0}
            )
            key = "ignored" if VERDICTS.get(row["verdict"], False) else "kept"
            bucket[key] += row["n"]
            bucket["total"] += row["n"]
        return tallies

    def suppressed_categories(self, project: str) -> Set[str]:
        """Categories this team has ignored enough times to stop surfacing."""
        suppressed: Set[str] = set()
        for category, tally in self.tallies(project).items():
            if any(exempt in category for exempt in _NEVER_SUPPRESSED):
                continue
            if tally["ignored"] < _SUPPRESSION_THRESHOLD:
                continue
            if tally["ignored"] / max(1, tally["total"]) >= 0.6:
                suppressed.add(category)
        return suppressed

    def apply(
        self, project: str, findings: Sequence[ReviewFinding]
    ) -> Tuple[List[ReviewFinding], List[str]]:
        """Filter findings through what this team has taught the reviewer."""
        suppressed = self.suppressed_categories(project)
        if not suppressed:
            return list(findings), []
        # Severity outranks preference: a P0 is posted no matter what the
        # category tallies say, so learned quiet can never hide a critical bug.
        kept = [
            finding
            for finding in findings
            if finding.severity == "P0" or finding.category not in suppressed
        ]
        return kept, sorted(suppressed)


# ── Confidence score ──────────────────────────────────────────────────────────

_SCORE_LABELS = (
    (5.0, "Production ready", "Merge"),
    (4.0, "Minor polish needed", "Merge after small fixes"),
    (3.0, "Implementation issues", "Address feedback first"),
    (2.0, "Significant bugs", "Needs rework"),
    (0.0, "Critical problems", "Major rethink needed"),
)

_SEVERITY_PENALTY = {"P0": 2.0, "P1": 0.7, "P2": 0.15}

#: How far each severity can drag the score down on its own. Without these, a
#: long tail of style nits sinks a PR further than one remote-code-execution
#: bug — which is exactly backwards, and trains people to ignore the score.
_SEVERITY_CAP = {"P0": 4.5, "P1": 2.0, "P2": 1.0}


def confidence_score(
    findings: Sequence[ReviewFinding], files: Sequence[FileDiff]
) -> Dict[str, Any]:
    """Score merge-readiness from 0 to 5.

    Three inputs, in the order they matter: the severity and number of open
    findings, how much surface the change covers, and whether it drifts from
    the patterns the codebase already follows.
    """
    score = 5.0
    penalties: List[str] = []

    by_severity = {badge: 0 for badge in SEVERITIES}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    severity_cost = sum(
        min(
            _SEVERITY_PENALTY.get(badge, 0.0) * count,
            _SEVERITY_CAP.get(badge, 4.5),
        )
        for badge, count in by_severity.items()
    )
    severity_cost = min(severity_cost, 4.5)
    if severity_cost:
        score -= severity_cost
        penalties.append(
            "issues: "
            + ", ".join(
                f"{count}×{badge}" for badge, count in by_severity.items() if count
            )
        )

    added_lines = sum(len(item.added) for item in files)
    touched = len([item for item in files if not item.binary])
    if touched > 25 or added_lines > 1200:
        score -= 0.5
        penalties.append(f"large change surface ({touched} files, {added_lines} lines)")
    elif touched > 10 or added_lines > 400:
        score -= 0.25
        penalties.append(f"broad change surface ({touched} files, {added_lines} lines)")

    drift = sum(1 for finding in findings if finding.category.startswith("convention:"))
    if drift:
        score -= min(0.5, 0.2 * drift)
        penalties.append(f"{drift} deviation(s) from established codebase patterns")

    score = max(0.0, min(5.0, score))
    rounded = round(score * 2) / 2  # nearest half point
    # A full 5/5 means "nothing to fix". Rounding must never hand that verdict
    # to a PR with an open comment on it — auto-approve keys off this number.
    if findings and rounded >= 5.0:
        rounded = 4.5
    label, verdict = next(
        (label, verdict)
        for threshold, label, verdict in _SCORE_LABELS
        if rounded >= threshold
    )
    return {
        "score": rounded,
        "out_of": 5,
        "label": label,
        "verdict": verdict,
        "penalties": penalties,
        "by_severity": by_severity,
    }


# ── Diagrams ──────────────────────────────────────────────────────────────────

_TABLE_PATTERNS = (
    re.compile(
        r"""(?:export\s+)?const\s+(?P<name>\w+)\s*=\s*\w*[Tt]able\s*\(\s*["'](?P<table>[\w.]+)["']"""
    ),
    re.compile(
        r"""CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?(?P<table>[\w.]+)""",
        re.IGNORECASE,
    ),
    re.compile(r"""__tablename__\s*=\s*["'](?P<table>\w+)["']"""),
)

_COLUMN_PATTERNS = (
    re.compile(r"""^\s*(?P<col>\w+)\s*:\s*(?P<type>\w+)\s*\(["']?(?P<db>[\w]*)["']?"""),
    re.compile(
        r"""^\s*(?P<col>\w+)\s*=\s*(?:mapped_column|Column)\s*\(\s*(?P<type>\w+)"""
    ),
    re.compile(
        r"""^\s*["'`]?(?P<col>\w+)["'`]?\s+(?P<type>VARCHAR|TEXT|INTEGER|INT|BIGINT|BOOLEAN|TIMESTAMP|UUID|SERIAL|NUMERIC|JSONB?)\b""",
        re.IGNORECASE,
    ),
)

_RELATION_RE = re.compile(
    r"""references\s*\(\s*\(\)\s*=>\s*(?P<target>\w+)|REFERENCES\s+["'`]?(?P<sql_target>\w+)|ForeignKey\s*\(\s*["'](?P<fk>[\w.]+)""",
    re.IGNORECASE,
)

_SERVICE_PATTERNS = (
    (r"\bstripe\b", "Stripe"),
    (r"\bsupabase\b", "Supabase"),
    (r"\bredis\b|ioredis", "Redis"),
    (r"\bs3\b|putObject|getObject", "S3"),
    (r"sendgrid|nodemailer|\bresend\b|\bses\b", "Email"),
    (r"\btwilio\b", "Twilio"),
    (r"expo-notifications|\bfcm\b|apns", "Push"),
    (r"\bopenai\b|anthropic", "LLM API"),
    (r"\bfetch\s*\(|axios\.|httpx\.|requests\.", "External API"),
    (r"\bdb\.|prisma\.|\.query\s*\(|session\.execute|supabase\.from", "Database"),
    (r"\bqueue\b|celery|bullmq|sqs", "Queue"),
)

_ROUTE_RE = re.compile(
    r"""(?:router|app)\.(?P<verb>get|post|put|patch|delete)\s*\(\s*["'`](?P<path>[^"'`]+)"""
    r"""|@(?:app|router)\.(?P<py_verb>get|post|put|patch|delete)\s*\(\s*["'](?P<py_path>[^"']+)""",
    re.IGNORECASE,
)

_CLASS_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:abstract\s+)?class\s+(?P<name>\w+)"""
    r"""(?:\s+extends\s+(?P<parent>\w+)|\s*\(\s*(?P<py_parent>\w+))?""",
)

_METHOD_RE = re.compile(
    r"""^\s{2,}(?:async\s+)?(?:public\s+|private\s+|protected\s+)?(?:def\s+)?(?P<name>\w+)\s*\("""
)


def _mermaid_escape(value: str) -> str:
    return re.sub(r'["\n\r]', " ", str(value)).strip()[:60]


def choose_diagram(files: Sequence[FileDiff]) -> str:
    """Pick the diagram that explains this change best."""
    source = "\n".join(item.added_source for item in files)
    paths = " ".join(item.path for item in files)

    if any(pattern.search(source) for pattern in _TABLE_PATTERNS) or re.search(
        r"\bmigrat|ALTER TABLE|add_column", paths + source, re.IGNORECASE
    ):
        return "er"
    if (
        _ROUTE_RE.search(source)
        or sum(
            1
            for pattern, _ in _SERVICE_PATTERNS
            if re.search(pattern, source, re.IGNORECASE)
        )
        >= 2
    ):
        return "sequence"
    class_hits = [line for line in source.splitlines() if _CLASS_RE.match(line)]
    if len(class_hits) >= 2 or any(
        "extends" in line or re.search(r"class\s+\w+\(\w+\)", line)
        for line in class_hits
    ):
        return "class"
    return "flow"


def build_diagram(
    files: Sequence[FileDiff], kind: Optional[str] = None
) -> Dict[str, str]:
    """Render a Mermaid diagram of the change, or an empty dict if nothing fits."""
    kind = kind or choose_diagram(files)
    builders = {
        "er": _er_diagram,
        "sequence": _sequence_diagram,
        "class": _class_diagram,
        "flow": _flow_diagram,
    }
    mermaid = builders.get(kind, _flow_diagram)(files)
    if not mermaid:
        return {}
    titles = {
        "er": "Entity relationships touched by this PR",
        "sequence": "Request flow through the changed code",
        "class": "Type hierarchy touched by this PR",
        "flow": "Control flow of the changed code",
    }
    return {
        "kind": kind,
        "title": titles.get(kind, "Change overview"),
        "mermaid": mermaid,
    }


def _er_diagram(files: Sequence[FileDiff]) -> str:
    entities: Dict[str, List[Tuple[str, str]]] = {}
    relations: Set[Tuple[str, str]] = set()
    for file_diff in files:
        current: Optional[str] = None
        for line in file_diff.added:
            text = line.text
            for pattern in _TABLE_PATTERNS:
                match = pattern.search(text)
                if match:
                    current = _mermaid_escape(match.group("table")).replace(".", "_")
                    entities.setdefault(current, [])
                    break
            if not current:
                continue
            for pattern in _COLUMN_PATTERNS:
                match = pattern.match(text)
                if match and len(entities[current]) < 12:
                    column = _mermaid_escape(match.group("col"))
                    column_type = _mermaid_escape(
                        match.groupdict().get("type") or "field"
                    )
                    if column and column not in {name for name, _ in entities[current]}:
                        entities[current].append((column, column_type))
                    break
            relation = _RELATION_RE.search(text)
            if relation:
                target = (
                    relation.group("target")
                    or relation.group("sql_target")
                    or (relation.group("fk") or "").split(".")[0]
                )
                if target:
                    relations.add((current, _mermaid_escape(target).replace(".", "_")))
    if not entities:
        return ""

    lines = ["erDiagram"]
    for source, target in sorted(relations):
        if source != target:
            lines.append(f"    {source} ||--o{{ {target} : references")
    for name, columns in list(entities.items())[:8]:
        lines.append(f"    {name} {{")
        for column, column_type in columns[:10]:
            safe_type = re.sub(r"\W", "_", column_type) or "field"
            lines.append(f"        {safe_type} {column}")
        lines.append("    }")
    return "\n".join(lines)


def _sequence_diagram(files: Sequence[FileDiff]) -> str:
    routes: List[Tuple[str, str]] = []
    services: List[str] = []
    for file_diff in files:
        source = file_diff.added_source
        for match in _ROUTE_RE.finditer(source):
            verb = (match.group("verb") or match.group("py_verb") or "").upper()
            path = match.group("path") or match.group("py_path") or ""
            if verb and path:
                routes.append((verb, _mermaid_escape(path)))
        for pattern, label in _SERVICE_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE) and label not in services:
                services.append(label)
    if not routes and not services:
        return ""

    handler = "Handler"
    lines = ["sequenceDiagram", "    autonumber", "    participant Client"]
    lines.append(f"    participant {handler}")
    for service in services[:5]:
        lines.append(f"    participant {service.replace(' ', '')} as {service}")

    if routes:
        for verb, path in routes[:4]:
            lines.append(f"    Client->>+{handler}: {verb} {path}")
            for service in services[:5]:
                token = service.replace(" ", "")
                lines.append(f"    {handler}->>+{token}: call")
                lines.append(f"    {token}-->>-{handler}: result")
            lines.append(f"    {handler}-->>-Client: response")
    else:
        lines.append(f"    Client->>+{handler}: invoke changed code")
        for service in services[:5]:
            token = service.replace(" ", "")
            lines.append(f"    {handler}->>+{token}: call")
            lines.append(f"    {token}-->>-{handler}: result")
        lines.append(f"    {handler}-->>-Client: response")
    return "\n".join(lines)


def _class_diagram(files: Sequence[FileDiff]) -> str:
    classes: Dict[str, Dict[str, Any]] = {}
    for file_diff in files:
        current: Optional[str] = None
        for line in file_diff.added:
            match = _CLASS_RE.match(line.text)
            if match:
                current = _mermaid_escape(match.group("name"))
                parent = match.group("parent") or match.group("py_parent")
                classes[current] = {
                    "parent": _mermaid_escape(parent) if parent else "",
                    "methods": [],
                }
                continue
            if current and len(classes[current]["methods"]) < 8:
                method = _METHOD_RE.match(line.text)
                if method and not method.group("name").startswith("__"):
                    classes[current]["methods"].append(
                        _mermaid_escape(method.group("name"))
                    )
    if not classes:
        return ""

    lines = ["classDiagram"]
    for name, meta in list(classes.items())[:8]:
        if meta["parent"] and meta["parent"] not in ("object",):
            lines.append(f"    {meta['parent']} <|-- {name}")
        lines.append(f"    class {name} {{")
        for method in meta["methods"][:8]:
            lines.append(f"        +{method}()")
        lines.append("    }")
    return "\n".join(lines)


def _flow_diagram(files: Sequence[FileDiff]) -> str:
    """A flowchart of the entry points the PR adds and where they branch."""
    nodes: List[str] = []
    edges: List[str] = []
    counter = 0
    for file_diff in files[:4]:
        changes = [
            item
            for item in symbol_changes(file_diff)
            if item.kind in ("added", "signature_changed", "modified")
        ]
        if not changes:
            continue
        counter += 1
        entry = f"F{counter}"
        nodes.append(
            f'    {entry}["{_mermaid_escape(os.path.basename(file_diff.path))}"]'
        )
        for index, change in enumerate(changes[:4]):
            node = f"{entry}S{index}"
            label = _mermaid_escape(change.name)
            shape = (
                "{%s}" % label
                if change.kind == "signature_changed"
                else '["%s()"]' % label
            )
            nodes.append(f"    {node}{shape}")
            edges.append(f"    {entry} --> {node}")
            guards = [
                line.text.strip()
                for line in file_diff.added
                if re.match(r"^\s*(?:if|elif|else if|switch|match)\b", line.text)
            ][:2]
            for guard_index, guard in enumerate(guards):
                guard_node = f"{node}G{guard_index}"
                nodes.append(f'    {guard_node}{{"{_mermaid_escape(guard)}"}}')
                edges.append(f"    {node} --> {guard_node}")
    if not nodes:
        return ""
    return "\n".join(["flowchart TD", *nodes, *edges])


# ── Auto-approve ──────────────────────────────────────────────────────────────


def auto_approve_decision(
    config: ReviewConfig,
    findings: Sequence[ReviewFinding],
    score: Dict[str, Any],
    files: Sequence[FileDiff],
    pull_request: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Decide whether this PR clears the bar for an automatic approval.

    Deliberately conservative: approval needs the policy switched on, a clean
    5/5 review, and every filter satisfied. Anything short of that is
    reported with the reason, so the decision is auditable.
    """
    policy = config.auto_approve
    pull_request = pull_request or {}

    if not policy.enabled:
        return {"approved": False, "reason": "autoApprove is not enabled"}

    if score.get("score", 0) < 5:
        return {
            "approved": False,
            "reason": f"confidence score is {score.get('score')}/5; auto-approve requires 5/5",
        }

    worst = _worst_risk(findings)
    if _RISK_RANK[worst] > _RISK_RANK[policy.risk_ceiling]:
        return {
            "approved": False,
            "reason": f"risk '{worst}' exceeds riskCeiling '{policy.risk_ceiling}'",
        }

    paths = [item.path for item in files]
    if policy.exclude_paths and any(
        matches_any_glob(policy.exclude_paths, path) for path in paths
    ):
        return {"approved": False, "reason": "PR touches a path in excludePaths"}
    if policy.include_paths and not all(
        matches_any_glob(policy.include_paths, path) for path in paths
    ):
        return {"approved": False, "reason": "PR touches a path outside includePaths"}

    from agents.review_config import _pr_author, _pr_base_branch, _pr_labels

    author = _pr_author(pull_request)
    if policy.exclude_authors and matches_any_glob(policy.exclude_authors, author):
        return {"approved": False, "reason": f"author '{author}' is excluded"}
    if policy.include_authors and not matches_any_glob(policy.include_authors, author):
        return {"approved": False, "reason": f"author '{author}' is not included"}

    branch = _pr_base_branch(pull_request)
    if policy.exclude_branches and matches_any_glob(policy.exclude_branches, branch):
        return {"approved": False, "reason": f"base branch '{branch}' is excluded"}
    if policy.include_branches and not matches_any_glob(
        policy.include_branches, branch
    ):
        return {"approved": False, "reason": f"base branch '{branch}' is not included"}

    labels = _pr_labels(pull_request)
    if policy.disabled_labels and any(
        matches_any_glob(policy.disabled_labels, label) for label in labels
    ):
        return {"approved": False, "reason": "PR carries a disabling label"}
    if policy.labels and not any(
        matches_any_glob(policy.labels, label) for label in labels
    ):
        return {"approved": False, "reason": "PR carries none of the required labels"}

    haystack = "{}\n{}".format(
        pull_request.get("title") or "", pull_request.get("body") or ""
    ).lower()
    if policy.ignore_keywords and any(
        keyword.lower() in haystack for keyword in policy.ignore_keywords
    ):
        return {"approved": False, "reason": "PR matches an ignoreKeywords entry"}
    if policy.include_keywords and not any(
        keyword.lower() in haystack for keyword in policy.include_keywords
    ):
        return {"approved": False, "reason": "PR matches no includeKeywords entry"}

    return {
        "approved": True,
        "reason": f"clean 5/5 review, risk '{worst}' within ceiling '{policy.risk_ceiling}'",
    }


def _worst_risk(findings: Sequence[ReviewFinding]) -> str:
    worst = "low"
    for finding in findings:
        risk = _SEVERITY_TO_RISK.get(finding.severity, "low")
        if _RISK_RANK[risk] > _RISK_RANK[worst]:
            worst = risk
    return worst


# ── Orchestration ─────────────────────────────────────────────────────────────


def _dedupe(findings: Sequence[ReviewFinding]) -> List[ReviewFinding]:
    """Collapse duplicates, keeping the most severe and most confident version."""
    best: Dict[Tuple[str, int, str], ReviewFinding] = {}
    for finding in findings:
        key = finding.key()
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            continue
        if (_SEVERITY_RANK[finding.severity], -finding.confidence) < (
            _SEVERITY_RANK[existing.severity],
            -existing.confidence,
        ):
            best[key] = finding
    return list(best.values())


def _sort_findings(findings: Sequence[ReviewFinding]) -> List[ReviewFinding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_RANK.get(item.severity, 9),
            -item.confidence,
            item.file,
            item.line,
        ),
    )


def run_review(
    repo_path: str = ".",
    diff: Optional[str] = None,
    base: Optional[str] = None,
    head: str = "HEAD",
    config: Optional[ReviewConfig] = None,
    overrides: Optional[Dict[str, Any]] = None,
    pull_request: Optional[Dict[str, Any]] = None,
    use_graph: bool = True,
    memory: Optional["ReviewMemory"] = None,
    max_workers: int = 8,
) -> Dict[str, Any]:
    """Review a pull request end to end and return the full result.

    Supply either ``diff`` (a unified diff) or ``base``/``head`` revisions to
    diff with git. The returned dict carries the findings, the confidence
    score, the diagram, the auto-approve decision, and rendered markdown.
    """
    repo_path = os.path.realpath(os.path.expanduser(repo_path))
    pull_request = pull_request or {}

    if diff is None:
        diff = diff_from_git(repo_path, base or "HEAD~1", head)

    config = config or load_review_config(repo_path, overrides=overrides)
    files = parse_unified_diff(diff)

    in_scope, scope_reason = (
        config.should_review(pull_request)
        if pull_request
        else (True, "no PR metadata supplied")
    )
    if not in_scope:
        return {
            "reviewed": False,
            "skipped_reason": scope_reason,
            "files_changed": len(files),
            "findings": [],
            "markdown": f"_Review skipped: {scope_reason}._",
        }

    reviewable = [item for item in files if _reviewable(item, config)]
    graph = _build_graph(repo_path) if (use_graph and reviewable) else None
    context = ReviewContext(
        repo_path=repo_path,
        files=files,
        config=config,
        graph=graph,
        pull_request=pull_request,
    )

    raw_findings: List[ReviewFinding] = []
    reviewer_status: Dict[str, Any] = {}
    if reviewable:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(SWARM)))
        ) as pool:
            futures = {pool.submit(reviewer, context): name for name, reviewer in SWARM}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    produced = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("Reviewer '%s' failed: %s", name, exc)
                    reviewer_status[name] = {
                        "ok": False,
                        "error": str(exc),
                        "findings": 0,
                    }
                    continue
                reviewer_status[name] = {"ok": True, "findings": len(produced)}
                raw_findings.extend(produced)

    findings = _dedupe(raw_findings)

    suppressed: List[str] = []
    if memory is not None:
        findings, suppressed = memory.apply(repo_path, findings)

    kept: List[ReviewFinding] = []
    for finding in findings:
        scoped = config.for_path(finding.file)
        if finding.comment_type not in scoped.comment_types:
            continue
        if not _passes_strictness(finding, scoped.strictness):
            continue
        kept.append(finding)
    findings = _sort_findings(kept)

    score = confidence_score(findings, files)
    diagram = (
        build_diagram(reviewable)
        if (config.sequence_diagram_section.included and reviewable)
        else {}
    )
    approval = auto_approve_decision(config, findings, score, files, pull_request)

    result: Dict[str, Any] = {
        "reviewed": True,
        "repo_path": repo_path,
        "files_changed": len(files),
        "files_reviewed": len(reviewable),
        "summary": _summarize(files, findings, score),
        "confidence": score,
        "findings": [finding.to_dict() for finding in findings],
        "findings_by_file": _group_by_file(findings, files),
        "diagram": diagram,
        "auto_approve": approval,
        "swarm": reviewer_status,
        "suppressed_categories": suppressed,
        "unenforceable_rules": [
            {"id": rule.id, "rule": rule.rule, "scope": rule.scope}
            for rule in unenforceable_rules(context)
        ],
        "config": {
            "strictness": config.strictness,
            "comment_types": list(config.comment_types),
            "sources": list(config.sources),
        },
        "graph": _graph_stats(graph),
    }
    result["markdown"] = render_review(result, config)
    return result


def _build_graph(repo_path: str) -> Any:
    try:
        from agents.knowledge_graph import CodebaseGraph

        return CodebaseGraph.build(repo_path)
    except Exception as exc:
        logger.warning("Codebase graph unavailable, reviewing diff-only: %s", exc)
        return None


def _graph_stats(graph: Any) -> Dict[str, Any]:
    if graph is None:
        return {"indexed": False}
    try:
        stats = dict(graph.stats())
    except Exception:  # pragma: no cover - defensive
        return {"indexed": False}
    stats["indexed"] = True
    return stats


def _group_by_file(
    findings: Sequence[ReviewFinding], files: Sequence[FileDiff]
) -> List[Dict[str, Any]]:
    by_path: Dict[str, List[ReviewFinding]] = {}
    for finding in findings:
        by_path.setdefault(finding.file, []).append(finding)
    rows = []
    for file_diff in files:
        items = by_path.get(file_diff.path, [])
        rows.append(
            {
                "file": file_diff.path,
                "status": file_diff.status,
                "added": len(file_diff.added),
                "removed": len(file_diff.removed),
                "issues": len(items),
                "worst": items[0].severity if items else "",
            }
        )
    return rows


# ── Summary and rendering ─────────────────────────────────────────────────────

_AREA_HINTS = (
    (r"(^|/)(api|routes?|controllers?|handlers?)(/|$)", "API layer"),
    (r"(^|/)(auth|login|session|oauth)", "authentication"),
    (r"(^|/)(db|database|models?|schema|migrations?)(/|$)", "data layer"),
    (r"(^|/)(components?|ui|views?|screens?|pages?)(/|$)", "UI"),
    (r"(^|/)(workers?|jobs?|tasks?|queues?)(/|$)", "background jobs"),
    (r"(^|/)(billing|payments?|stripe|subscriptions?)", "billing"),
    (r"(^|/)(infra|terraform|k8s|deploy|\.github)(/|$)", "infrastructure"),
    (r"(^|/)(tests?|__tests__|spec)(/|$)", "tests"),
)


def _areas_touched(files: Sequence[FileDiff]) -> List[str]:
    areas: List[str] = []
    for file_diff in files:
        for pattern, label in _AREA_HINTS:
            if re.search(pattern, file_diff.path, re.IGNORECASE) and label not in areas:
                areas.append(label)
    return areas


def _summarize(
    files: Sequence[FileDiff],
    findings: Sequence[ReviewFinding],
    score: Dict[str, Any],
) -> str:
    """Plain-language account of what the PR does and what the review found."""
    if not files:
        return "No reviewable changes in this diff."

    added = sum(len(item.added) for item in files)
    removed = sum(len(item.removed) for item in files)
    new_files = [item for item in files if item.status == "added"]
    areas = _areas_touched(files)

    parts = [
        f"This PR touches **{len(files)} file(s)** "
        f"(+{added}/−{removed})"
        + (f", including {len(new_files)} new file(s)" if new_files else "")
        + "."
    ]
    if areas:
        parts.append(f"It changes the {_join_human(areas)}.")

    symbols = [
        change
        for file_diff in files
        for change in symbol_changes(file_diff)
        if change.kind in ("added", "signature_changed", "removed")
    ]
    if symbols:
        added_names = [item.name for item in symbols if item.kind == "added"][:4]
        resigned = [item.name for item in symbols if item.kind == "signature_changed"]
        removed_names = [item.name for item in symbols if item.kind == "removed"][:3]
        if added_names:
            parts.append(f"New symbols: {_join_code(added_names)}.")
        if resigned:
            parts.append(f"Changed signatures: {_join_code(resigned[:4])}.")
        if removed_names:
            parts.append(f"Removed: {_join_code(removed_names)}.")

    if not findings:
        parts.append("The review found no issues that meet the configured threshold.")
    else:
        counts = score.get("by_severity", {})
        breakdown = ", ".join(
            f"{counts[badge]} {badge} ({SEVERITY_LABELS[badge].lower()})"
            for badge in SEVERITIES
            if counts.get(badge)
        )
        parts.append(f"The review raised {len(findings)} issue(s): {breakdown}.")
        headline = findings[0]
        parts.append(
            f"The most serious is in `{headline.file}`: {headline.title.rstrip('.')}."
        )

    return " ".join(parts)


def _join_human(items: Sequence[str]) -> str:
    items = list(items)
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _join_code(items: Sequence[str]) -> str:
    return _join_human([f"`{item}`" for item in items])


def _wrap_section(title: str, body: str, section: Any) -> str:
    """Render one review section, collapsing it when configured to."""
    if not body.strip():
        return ""
    if getattr(section, "collapsible", False):
        open_attr = " open" if getattr(section, "default_open", True) else ""
        return f"<details{open_attr}>\n<summary><b>{title}</b></summary>\n\n{body}\n\n</details>"
    return f"## {title}\n\n{body}"


def render_review(result: Dict[str, Any], config: ReviewConfig) -> str:
    """Render the review as the markdown body of a PR comment."""
    if not result.get("reviewed", True):
        return f"_Review skipped: {result.get('skipped_reason', 'out of scope')}._"

    blocks: List[str] = []

    if config.summary_section.included:
        blocks.append(
            _wrap_section("Review summary", result["summary"], config.summary_section)
        )

    if config.confidence_score_section.included:
        score = result["confidence"]
        body = [
            f"### {score['score']}/{score['out_of']} — {score['label']}",
            "",
            f"**Recommendation:** {score['verdict']}",
        ]
        if score["penalties"]:
            body.append("")
            body.append("Weighed against:")
            body.extend(f"- {item}" for item in score["penalties"])
        blocks.append(
            _wrap_section(
                "Confidence score", "\n".join(body), config.confidence_score_section
            )
        )

    if config.issues_table_section.included and result["findings"]:
        rows = [
            "| Severity | Type | Location | Issue |",
            "| --- | --- | --- | --- |",
        ]
        for finding in result["findings"]:
            title = finding["title"].replace("|", "\\|")
            rows.append(
                f"| **{finding['severity']}** {SEVERITY_LABELS.get(finding['severity'], '')} "
                f"| {finding['comment_type']} "
                f"| `{finding['file']}:{finding['line']}` "
                f"| {title} |"
            )
        blocks.append(
            _wrap_section("Issues found", "\n".join(rows), config.issues_table_section)
        )

    if config.issues_table_section.included and result.get("findings_by_file"):
        rows = ["| File | Change | Issues |", "| --- | --- | --- |"]
        for row in result["findings_by_file"]:
            marker = f" (worst {row['worst']})" if row["worst"] else ""
            rows.append(
                f"| `{row['file']}` | {row['status']} +{row['added']}/−{row['removed']} "
                f"| {row['issues']}{marker} |"
            )
        blocks.append(
            _wrap_section("Files changed", "\n".join(rows), config.issues_table_section)
        )

    diagram = result.get("diagram") or {}
    if config.sequence_diagram_section.included and diagram.get("mermaid"):
        body = f"{diagram['title']}\n\n```mermaid\n{diagram['mermaid']}\n```"
        blocks.append(_wrap_section("Diagram", body, config.sequence_diagram_section))

    if not config.update_summary_only and result["findings"]:
        blocks.append("## Inline comments\n\n" + render_inline_comments(result, config))

    approval = result.get("auto_approve") or {}
    if approval.get("approved"):
        blocks.append(f"✅ **Auto-approved** — {approval['reason']}.")

    if result.get("suppressed_categories"):
        blocks.append(
            "_Suppressed by learned preferences: "
            + ", ".join(f"`{item}`" for item in result["suppressed_categories"])
            + "._"
        )

    if not config.hide_footer:
        graph = result.get("graph") or {}
        indexed = (
            f"{graph.get('symbols', 0)} symbols and {graph.get('calls', 0)} call edges "
            f"across {graph.get('files', 0)} indexed files"
            if graph.get("indexed")
            else "diff-only (codebase graph unavailable)"
        )
        reviewers = ", ".join(sorted(result.get("swarm", {})))
        blocks.append(
            "---\n"
            f"<sub>Reviewed {result['files_reviewed']}/{result['files_changed']} changed files · "
            f"swarm: {reviewers} · context: {indexed}</sub>"
        )

    return "\n\n".join(block for block in blocks if block.strip())


def render_inline_comments(result: Dict[str, Any], config: ReviewConfig) -> str:
    """Render findings as the inline comments a reviewer would leave on the diff."""
    chunks: List[str] = []
    for finding in result["findings"]:
        header = (
            f"**{finding['severity']} · {SEVERITY_LABELS.get(finding['severity'], '')}** "
            f"(`{finding['comment_type']}`) — `{finding['file']}:{finding['line']}`"
        )
        lines = [header, "", finding["title"]]
        if finding["body"]:
            lines += ["", finding["body"]]
        if finding["evidence"]:
            lines += ["", "<sub>" + " · ".join(finding["evidence"]) + "</sub>"]
        if finding["suggestion"]:
            lines += ["", "```suggestion", finding["suggestion"].rstrip(), "```"]
        if config.fix_with_ai:
            lines += [
                "",
                "<details><summary>Fix with your agent</summary>",
                "",
                "```",
                f"In {finding['file']} around line {finding['line']}: {finding['title']}",
                (finding["body"] or "").strip(),
                "```",
                "",
                "</details>",
            ]
        chunks.append("\n".join(line for line in lines if line is not None))
    return "\n\n---\n\n".join(chunks)


# ── Agent ─────────────────────────────────────────────────────────────────────


class PRReviewAgent(BaseAgent):
    """A pull request reviewer with the whole codebase in context.

    Indexes the repository into a graph, runs a swarm of specialist
    reviewers over the diff in parallel, and reports what a senior engineer
    would: severity-badged inline comments with suggested fixes, a 0–5
    confidence score, an issues table, and a diagram of the change.

    Every tool below runs without an API key. Providing one additionally
    lets the agent be used conversationally, where it calls these same tools.
    """

    name = "pr_review"
    description = (
        "Reviews pull requests with full codebase context — graph-indexed impact "
        "analysis, a parallel reviewer swarm, confidence scoring, and learned "
        "suppression of comment types the team keeps dismissing."
    )
    model = "gpt-5"

    system_prompt = """\
You are a senior engineer reviewing a pull request. You have the whole codebase \
indexed as a graph, not just the diff.

HOW YOU REVIEW

1. Start with `review_pull_request`. It runs the deterministic swarm — security, \
logic, cross-file impact, conventions, performance, dependencies, custom rules, \
and test coverage — and returns findings, a confidence score, and a diagram.
2. Read the findings it returns as the floor, not the ceiling. Your job is what \
static detectors cannot do: trace whether the change is *correct* in context.
3. Use `explain_impact` on any symbol the diff changes to see who calls it. A \
change that looks fine in isolation is often wrong for one of its callers.
4. Apply the repository's own rules. `review_pull_request` reports \
`unenforceable_rules` — rules from greptile.json or .greptile/ that need \
judgement rather than a regex. Evaluate each one against the diff yourself.

WHAT EARNS A COMMENT

- P0: security vulnerabilities, data loss, crashes, breaking changes to callers \
outside the PR. Must fix before merging.
- P1: bugs, incorrect behaviour, unhandled edge cases. Should fix.
- P2: code quality, maintainability, convention drift. Consider fixing.

Every comment names a concrete failure — the input, state, or sequence that makes \
the code behave wrong — and cites evidence from the codebase, not a general \
principle. If you cannot describe how it breaks, do not post it.

WHAT DOES NOT EARN A COMMENT

Formatting a linter already handles. Restating what the code does. Style \
preferences the codebase does not itself follow. Speculation about code you have \
not read — call `explain_impact` or read the file instead.

Be direct and specific. Lead with the problem, then the fix. Reviewers read \
dozens of these; every sentence should earn its place.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_pull_request",
                "description": (
                    "Run the full review swarm over a diff and return findings, a 0-5 "
                    "confidence score, a Mermaid diagram, and the auto-approve decision."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Path to the repository checkout. Defaults to the current directory.",
                        },
                        "diff": {
                            "type": "string",
                            "description": "Unified diff to review. Omit to diff with git instead.",
                        },
                        "base": {
                            "type": "string",
                            "description": "Base revision when diffing with git (default HEAD~1).",
                        },
                        "head": {
                            "type": "string",
                            "description": "Head revision when diffing with git (default HEAD).",
                        },
                        "strictness": {
                            "type": "integer",
                            "description": "Override configured strictness: 1 verbose, 2 balanced, 3 critical only.",
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "index_codebase",
                "description": (
                    "Build or refresh the codebase graph — files, functions, classes, "
                    "imports, calls — and report what was indexed."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string"},
                    },
                    "required": [],
                },
            },
            {
                "name": "explain_impact",
                "description": (
                    "Trace a symbol through the codebase graph: who calls it, which "
                    "files import it, and what it reaches."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "symbol": {
                            "type": "string",
                            "description": "Function, class, or module name to trace.",
                        },
                        "repo_path": {"type": "string"},
                    },
                    "required": ["symbol"],
                },
            },
            {
                "name": "check_review_scope",
                "description": (
                    "Check whether a PR is in scope for review under the repository's "
                    "configured filters, and say why when it is not."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string"},
                        "pull_request": {
                            "type": "object",
                            "description": "PR metadata: title, body, draft, labels, user, base, event.",
                        },
                    },
                    "required": ["pull_request"],
                },
            },
            {
                "name": "record_review_feedback",
                "description": (
                    "Record a reaction to a review comment so the reviewer learns. "
                    "Verdicts: upvote, downvote, addressed, ignored."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "verdict": {
                            "type": "string",
                            "enum": sorted(VERDICTS),
                        },
                        "repo_path": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                    },
                    "required": ["category", "verdict"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_pull_request": self._review_pull_request,
            "index_codebase": self._index_codebase,
            "explain_impact": self._explain_impact,
            "check_review_scope": self._check_review_scope,
            "record_review_feedback": self._record_review_feedback,
        }

    # ── Tool handlers ────────────────────────────────────────────────────

    def _review_pull_request(
        self,
        repo_path: str = ".",
        diff: str = "",
        base: str = "",
        head: str = "HEAD",
        strictness: Optional[int] = None,
        pull_request: Optional[Dict[str, Any]] = None,
        use_memory: bool = True,
    ) -> Dict[str, Any]:
        overrides = {"strictness": strictness} if strictness else None
        memory: Optional[ReviewMemory] = None
        if use_memory:
            try:
                memory = ReviewMemory()
            except Exception as exc:
                logger.debug("Review memory unavailable: %s", exc)
        try:
            return run_review(
                repo_path=repo_path or ".",
                diff=diff or None,
                base=base or None,
                head=head or "HEAD",
                overrides=overrides,
                pull_request=pull_request,
                memory=memory,
            )
        finally:
            if memory is not None:
                memory.close()

    def _index_codebase(self, repo_path: str = ".") -> Dict[str, Any]:
        graph = _build_graph(os.path.expanduser(repo_path or "."))
        stats = _graph_stats(graph)
        if graph is not None:
            graph.close()
        if not stats.get("indexed"):
            return {"indexed": False, "error": "codebase graph could not be built"}
        return stats

    def _explain_impact(self, symbol: str, repo_path: str = ".") -> Dict[str, Any]:
        repo_path = os.path.realpath(os.path.expanduser(repo_path or "."))
        graph = _build_graph(repo_path)
        if graph is None:
            return {"symbol": symbol, "error": "codebase graph could not be built"}
        try:
            callers = graph.find_callers(symbol)
            importers = graph.find_importers(symbol)
            definitions = graph.find_symbols(symbol)
            return {
                "symbol": symbol,
                "defined_at": [
                    {
                        "file": _relative(str(row.get("file", "")), repo_path),
                        "line": row.get("line"),
                        "kind": row.get("kind"),
                        "signature": row.get("signature"),
                    }
                    for row in definitions[:10]
                ],
                "called_by": _format_call_sites(callers, repo_path),
                "imported_by": _format_call_sites(importers, repo_path),
                "caller_count": len(callers),
                "importer_count": len(importers),
                "blast_radius": (
                    "wide"
                    if len(callers) + len(importers) > 20
                    else "moderate" if len(callers) + len(importers) > 5 else "narrow"
                ),
            }
        finally:
            graph.close()

    def _check_review_scope(
        self, pull_request: Dict[str, Any], repo_path: str = "."
    ) -> Dict[str, Any]:
        config = load_review_config(os.path.expanduser(repo_path or "."))
        in_scope, reason = config.should_review(pull_request or {})
        return {
            "in_scope": in_scope,
            "reason": reason,
            "strictness": config.strictness,
            "comment_types": list(config.comment_types),
            "auto_review": list(config.auto_review),
            "config_sources": list(config.sources) or ["defaults"],
        }

    def _record_review_feedback(
        self,
        category: str,
        verdict: str,
        repo_path: str = ".",
        title: str = "",
        severity: str = "",
    ) -> Dict[str, Any]:
        project = os.path.realpath(os.path.expanduser(repo_path or "."))
        with ReviewMemory() as memory:
            recorded = memory.record(
                project,
                {"category": category, "title": title, "severity": severity},
                verdict,
            )
            recorded["suppressed_categories"] = sorted(
                memory.suppressed_categories(project)
            )
        return recorded

    # ── Convenience API ──────────────────────────────────────────────────

    def review_pull_request(self, **kwargs: Any) -> Dict[str, Any]:
        """Review a PR directly, without going through the model."""
        return self._review_pull_request(**kwargs)


__all__ = [
    "SEVERITIES",
    "SEVERITY_LABELS",
    "SWARM",
    "VERDICTS",
    "FileDiff",
    "PRReviewAgent",
    "ReviewContext",
    "ReviewFinding",
    "ReviewMemory",
    "auto_approve_decision",
    "build_diagram",
    "choose_diagram",
    "clear_caches",
    "confidence_score",
    "diff_from_git",
    "parse_unified_diff",
    "render_inline_comments",
    "render_review",
    "run_review",
    "symbol_changes",
]
