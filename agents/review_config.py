"""
Review configuration — ``greptile.json`` and cascading ``.greptile/`` folders.

Implements the configuration surface an AI PR reviewer needs: a repo-root
``greptile.json``, plus ``.greptile/`` directories at any depth that layer
directory-scoped settings on top of it.

Three files make up a ``.greptile/`` folder:

``config.json``
    Review settings, PR filters, output sections, auto-approve policy, and
    structured rules.
``rules.md``
    Free-form prose guidance that applies to the whole directory tree.
``files.json``
    Repository files to pull in as review context (schemas, specs, ADRs),
    optionally scoped to the files being reviewed.

Usage::

    from agents.review_config import load_review_config

    config = load_review_config("/path/to/repo")
    if config.should_review(pr)[0]:
        scoped = config.for_path("src/api/billing.ts")
        print(scoped.strictness, scoped.rules)
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

CONFIG_DIR = ".greptile"
ROOT_CONFIG_FILE = "greptile.json"

#: Comment categories a reviewer may emit.
COMMENT_TYPES = ("logic", "syntax", "style")

#: Events that can trigger an automatic review.
REVIEW_TRIGGERS = ("open", "push", "rebase")

#: Ordered risk ladder — used to pick the strictest ceiling when merging.
RISK_LEVELS = ("low", "medium", "high", "critical")

#: Rule severities, ordered low to high.
RULE_SEVERITIES = ("low", "medium", "high")

_MAX_CONFIG_BYTES = 512 * 1024

_SKIP_SCAN_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".expo",
    "coverage",
    "vendor",
    ".turbo",
}


# ── Glob matching ─────────────────────────────────────────────────────────────


def _translate_glob(pattern: str) -> str:
    """Translate one glob pattern into a regex body.

    Supports ``*`` (within a path segment), ``**`` (across segments), ``?``
    (a single non-separator character), and ``{a,b}`` alternation. Negation
    is deliberately unsupported, matching the documented behaviour.
    """
    out: List[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                index += 2
                if pattern.startswith("/", index):
                    # `a/**/b` should also match `a/b` — the middle is optional.
                    index += 1
                    out.append("(?:[^/]+/)*")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        elif char == "{":
            close = pattern.find("}", index)
            if close == -1:
                out.append(re.escape(char))
                index += 1
                continue
            alternatives = pattern[index + 1 : close].split(",")
            out.append("(?:" + "|".join(_translate_glob(a) for a in alternatives) + ")")
            index = close + 1
        else:
            out.append(re.escape(char))
            index += 1
    return "".join(out)


def matches_glob(pattern: str, path: str) -> bool:
    """True when ``path`` matches ``pattern``.

    Matching is case-insensitive. A pattern with no ``/`` matches at any
    depth (``*.md`` matches ``docs/readme.md``), and a pattern ending in
    ``/`` matches everything beneath that directory — both are .gitignore
    conventions that people reasonably expect from ``ignorePatterns``.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    path = (path or "").replace("\\", "/").lstrip("./")
    if pattern.endswith("/"):
        pattern += "**"
    anchored = pattern.lstrip("/")
    bodies = [_translate_glob(anchored)]
    if "/" not in anchored.replace("**", ""):
        # Depth-agnostic: `*.md` should also catch `docs/notes.md`.
        bodies.append("(?:.*/)?" + _translate_glob(anchored))
    return any(re.fullmatch(body, path, re.IGNORECASE) for body in bodies)


def matches_any_glob(patterns: Sequence[str], path: str) -> bool:
    return any(matches_glob(p, path) for p in patterns or ())


def _split_lines(value: Any) -> List[str]:
    """Normalise a newline-separated string (or list) into a clean list."""
    if not value:
        return []
    if isinstance(value, str):
        items = value.splitlines()
    elif isinstance(value, (list, tuple)):
        items = [str(item) for item in value]
    else:
        return []
    return [item.strip() for item in items if item and item.strip()]


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class Rule:
    """One structured review rule from ``config.json`` or ``greptile.json``."""

    rule: str
    id: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    severity: str = "medium"
    enabled: bool = True
    source: str = ""

    def applies_to(self, path: str) -> bool:
        if not self.enabled:
            return False
        if not self.scope:
            return True
        return matches_any_glob(self.scope, path)

    @classmethod
    def parse(cls, raw: Any, source: str = "") -> Optional["Rule"]:
        if isinstance(raw, str):
            text = raw.strip()
            return cls(rule=text, source=source) if text else None
        if not isinstance(raw, dict):
            return None
        text = str(raw.get("rule") or "").strip()
        if not text:
            return None
        severity = str(raw.get("severity") or "medium").lower()
        if severity not in RULE_SEVERITIES:
            severity = "medium"
        return cls(
            rule=text,
            id=raw.get("id"),
            scope=_split_lines(raw.get("scope")),
            severity=severity,
            enabled=bool(raw.get("enabled", True)),
            source=source,
        )


@dataclass
class ContextFile:
    """A repository file pulled in as review context."""

    path: str
    description: str = ""
    scope: List[str] = field(default_factory=list)
    source: str = ""

    def applies_to(self, path: str) -> bool:
        if not self.scope:
            return True
        return matches_any_glob(self.scope, path)

    @classmethod
    def parse(cls, raw: Any, source: str = "") -> Optional["ContextFile"]:
        if isinstance(raw, str):
            return cls(path=raw.strip(), source=source) if raw.strip() else None
        if not isinstance(raw, dict):
            return None
        path = str(raw.get("path") or "").strip()
        if not path:
            return None
        return cls(
            path=path,
            description=str(raw.get("description") or ""),
            scope=_split_lines(raw.get("scope")),
            source=source,
        )


@dataclass
class Section:
    """Visibility and collapse behaviour for one review output section."""

    included: bool = True
    collapsible: bool = False
    default_open: bool = True

    @classmethod
    def parse(cls, raw: Any, default_included: bool = True) -> "Section":
        if not isinstance(raw, dict):
            return cls(included=default_included)
        return cls(
            included=bool(raw.get("included", default_included)),
            collapsible=bool(raw.get("collapsible", False)),
            default_open=bool(raw.get("defaultOpen", True)),
        )


@dataclass
class AutoApprovePolicy:
    """When the reviewer may approve a PR on its own."""

    enabled: bool = False
    risk_ceiling: str = "low"
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    include_authors: List[str] = field(default_factory=list)
    exclude_authors: List[str] = field(default_factory=list)
    include_branches: List[str] = field(default_factory=list)
    exclude_branches: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    disabled_labels: List[str] = field(default_factory=list)
    include_keywords: List[str] = field(default_factory=list)
    ignore_keywords: List[str] = field(default_factory=list)

    @classmethod
    def parse(cls, raw: Any) -> "AutoApprovePolicy":
        if not isinstance(raw, dict):
            return cls()
        filters = raw.get("filters") if isinstance(raw.get("filters"), dict) else {}
        ceiling = str(raw.get("riskCeiling") or "low").lower()
        if ceiling not in RISK_LEVELS:
            ceiling = "low"
        return cls(
            enabled=bool(raw.get("enabled", False)),
            risk_ceiling=ceiling,
            include_paths=_split_lines(filters.get("includePaths")),
            exclude_paths=_split_lines(filters.get("excludePaths")),
            include_authors=_split_lines(filters.get("includeAuthors")),
            exclude_authors=_split_lines(filters.get("excludeAuthors")),
            include_branches=_split_lines(filters.get("includeBranches")),
            exclude_branches=_split_lines(filters.get("excludeBranches")),
            labels=_split_lines(filters.get("labels")),
            disabled_labels=_split_lines(filters.get("disabledLabels")),
            include_keywords=_split_lines(filters.get("includeKeywords")),
            ignore_keywords=_split_lines(filters.get("ignoreKeywords")),
        )

    def merge(self, child: "AutoApprovePolicy") -> "AutoApprovePolicy":
        """Strictest-wins merge of a child policy onto this one.

        A nested directory can only ever tighten auto-approval: ``enabled``
        must hold everywhere the PR touches, exclusions union, inclusions
        intersect, and the lower risk ceiling prevails.
        """
        include_paths = _intersect(self.include_paths, child.include_paths)
        include_authors = _intersect(self.include_authors, child.include_authors)
        include_branches = _intersect(self.include_branches, child.include_branches)
        include_keywords = _intersect(self.include_keywords, child.include_keywords)
        labels = _intersect(self.labels, child.labels)
        return AutoApprovePolicy(
            enabled=self.enabled and child.enabled,
            risk_ceiling=min(
                self.risk_ceiling, child.risk_ceiling, key=RISK_LEVELS.index
            ),
            include_paths=include_paths,
            exclude_paths=_union(self.exclude_paths, child.exclude_paths),
            include_authors=include_authors,
            exclude_authors=_union(self.exclude_authors, child.exclude_authors),
            include_branches=include_branches,
            exclude_branches=_union(self.exclude_branches, child.exclude_branches),
            labels=labels,
            disabled_labels=_union(self.disabled_labels, child.disabled_labels),
            include_keywords=include_keywords,
            ignore_keywords=_union(self.ignore_keywords, child.ignore_keywords),
        )


def _union(left: Sequence[str], right: Sequence[str]) -> List[str]:
    seen: List[str] = list(left)
    for item in right:
        if item not in seen:
            seen.append(item)
    return seen


def _intersect(left: Sequence[str], right: Sequence[str]) -> List[str]:
    """Intersect two include-lists, treating empty as "no restriction"."""
    if not left:
        return list(right)
    if not right:
        return list(left)
    return [item for item in left if item in right]


@dataclass
class ReviewConfig:
    """Effective review configuration for a repository or a directory within it."""

    # Review behaviour
    strictness: int = 2
    comment_types: List[str] = field(default_factory=lambda: list(COMMENT_TYPES))
    auto_review: List[str] = field(default_factory=lambda: ["open"])
    trigger_on_drafts: bool = False

    # PR filters
    labels: List[str] = field(default_factory=list)
    disabled_labels: List[str] = field(default_factory=list)
    include_authors: List[str] = field(default_factory=list)
    exclude_authors: List[str] = field(default_factory=list)
    include_branches: List[str] = field(default_factory=list)
    exclude_branches: List[str] = field(default_factory=list)
    include_keywords: List[str] = field(default_factory=list)
    ignore_keywords: List[str] = field(default_factory=list)
    ignore_patterns: List[str] = field(default_factory=list)

    # Context
    instructions: str = ""
    rules: List[Rule] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    context_files: List[ContextFile] = field(default_factory=list)
    prose_rules: List[str] = field(default_factory=list)
    context_repos: List[str] = field(default_factory=list)
    pattern_repositories: List[str] = field(default_factory=list)

    # Output
    should_update_description: bool = False
    update_summary_only: bool = False
    fix_with_ai: bool = True
    hide_footer: bool = False
    status_check: bool = True
    status_comments_enabled: bool = True
    summary_section: Section = field(default_factory=Section)
    issues_table_section: Section = field(default_factory=Section)
    confidence_score_section: Section = field(default_factory=Section)
    sequence_diagram_section: Section = field(default_factory=Section)

    auto_approve: AutoApprovePolicy = field(default_factory=AutoApprovePolicy)

    # Bookkeeping
    repo_root: str = ""
    sources: List[str] = field(default_factory=list)
    _scoped: Dict[str, Dict[str, Any]] = field(default_factory=dict, repr=False)
    _auto_approve_set: bool = field(default=False, repr=False)

    # ── Filters ──────────────────────────────────────────────────────────

    def is_ignored(self, path: str) -> bool:
        """True when ``path`` is excluded from review by ``ignorePatterns``."""
        return matches_any_glob(self.ignore_patterns, path)

    def should_review(self, pull_request: Dict[str, Any]) -> Tuple[bool, str]:
        """Decide whether a PR is in scope, and say why when it is not.

        ``pull_request`` accepts the GitHub webhook shape loosely: ``title``,
        ``body``, ``draft``, ``labels``, ``user.login`` / ``author``,
        ``base.ref`` / ``base_branch``, and ``event``.
        """
        event = str(pull_request.get("event") or "open").lower()
        if event in REVIEW_TRIGGERS and event not in self.auto_review:
            return (
                False,
                f"'{event}' is not in autoReview ({', '.join(self.auto_review) or 'none'})",
            )

        if pull_request.get("draft") and not self.trigger_on_drafts:
            return False, "PR is a draft and triggerOnDrafts is false"

        labels = _pr_labels(pull_request)
        if self.disabled_labels and any(
            matches_any_glob(self.disabled_labels, label) for label in labels
        ):
            return False, "PR carries a label listed in disabledLabels"
        if self.labels and not any(
            matches_any_glob(self.labels, label) for label in labels
        ):
            return False, "PR carries none of the labels listed in labels"

        author = _pr_author(pull_request)
        if self.exclude_authors and matches_any_glob(self.exclude_authors, author):
            return False, f"author '{author}' is in excludeAuthors"
        if self.include_authors and not matches_any_glob(self.include_authors, author):
            return False, f"author '{author}' is not in includeAuthors"

        branch = _pr_base_branch(pull_request)
        if self.exclude_branches and matches_any_glob(self.exclude_branches, branch):
            return False, f"base branch '{branch}' is in excludeBranches"
        if self.include_branches and not matches_any_glob(
            self.include_branches, branch
        ):
            return False, f"base branch '{branch}' is not in includeBranches"

        haystack = "{}\n{}".format(
            pull_request.get("title") or "", pull_request.get("body") or ""
        ).lower()
        if self.ignore_keywords and any(
            keyword.lower() in haystack for keyword in self.ignore_keywords
        ):
            return False, "PR title/description matches an ignoreKeywords entry"
        if self.include_keywords and not any(
            keyword.lower() in haystack for keyword in self.include_keywords
        ):
            return False, "PR title/description matches no includeKeywords entry"

        return True, "in scope"

    # ── Scoping ──────────────────────────────────────────────────────────

    def rules_for(self, path: str) -> List[Rule]:
        """Active rules that apply to ``path``, with disabled IDs removed."""
        disabled = {rule_id for rule_id in self.disabled_rules if rule_id}
        return [
            rule
            for rule in self.rules
            if rule.applies_to(path) and (rule.id not in disabled)
        ]

    def context_files_for(self, path: str) -> List[ContextFile]:
        return [item for item in self.context_files if item.applies_to(path)]

    def for_path(self, path: str) -> "ReviewConfig":
        """Return the effective config at ``path``, applying the cascade.

        Directory-scoped ``.greptile/`` folders layer onto their parents:
        scalars from the deepest folder win, rules and context files
        accumulate, and the auto-approve policy merges strictest-wins.
        """
        if not self._scoped:
            return self
        normalized = (path or "").replace("\\", "/").strip("/")
        directory = os.path.dirname(normalized)
        chain: List[str] = []
        parts = [part for part in directory.split("/") if part] if directory else []
        for depth in range(len(parts) + 1):
            candidate = "/".join(parts[:depth])
            if candidate and candidate in self._scoped:
                chain.append(candidate)
        if not chain:
            return self
        config = self
        for key in chain:
            config = _apply_raw(config, self._scoped[key], source=f"{key}/{CONFIG_DIR}")
        return config

    # ── Serialisation ────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Round-trip back to the JSON shape, for `agents review --show-config`."""
        return {
            "strictness": self.strictness,
            "commentTypes": list(self.comment_types),
            "autoReview": list(self.auto_review),
            "triggerOnDrafts": self.trigger_on_drafts,
            "labels": list(self.labels),
            "disabledLabels": list(self.disabled_labels),
            "includeAuthors": list(self.include_authors),
            "excludeAuthors": list(self.exclude_authors),
            "includeBranches": list(self.include_branches),
            "excludeBranches": list(self.exclude_branches),
            "includeKeywords": list(self.include_keywords),
            "ignoreKeywords": list(self.ignore_keywords),
            "ignorePatterns": list(self.ignore_patterns),
            "instructions": self.instructions,
            "rules": [
                {
                    "rule": rule.rule,
                    "id": rule.id,
                    "scope": rule.scope,
                    "severity": rule.severity,
                    "enabled": rule.enabled,
                    "source": rule.source,
                }
                for rule in self.rules
            ],
            "disabledRules": list(self.disabled_rules),
            "customContext": {
                "files": [
                    {
                        "path": item.path,
                        "description": item.description,
                        "scope": item.scope,
                    }
                    for item in self.context_files
                ]
            },
            "context": {"repos": list(self.context_repos)},
            "patternRepositories": list(self.pattern_repositories),
            "shouldUpdateDescription": self.should_update_description,
            "updateSummaryOnly": self.update_summary_only,
            "fixWithAI": self.fix_with_ai,
            "hideFooter": self.hide_footer,
            "statusCheck": self.status_check,
            "statusCommentsEnabled": self.status_comments_enabled,
            "autoApprove": {
                "enabled": self.auto_approve.enabled,
                "riskCeiling": self.auto_approve.risk_ceiling,
            },
            "sources": list(self.sources),
        }


def _pr_labels(pull_request: Dict[str, Any]) -> List[str]:
    raw = pull_request.get("labels") or []
    labels: List[str] = []
    for item in raw:
        if isinstance(item, dict):
            name = item.get("name")
            if name:
                labels.append(str(name))
        elif item:
            labels.append(str(item))
    return labels


def _pr_author(pull_request: Dict[str, Any]) -> str:
    user = pull_request.get("user")
    if isinstance(user, dict) and user.get("login"):
        return str(user["login"])
    return str(pull_request.get("author") or "")


def _pr_base_branch(pull_request: Dict[str, Any]) -> str:
    base = pull_request.get("base")
    if isinstance(base, dict) and base.get("ref"):
        return str(base["ref"])
    return str(pull_request.get("base_branch") or pull_request.get("base") or "")


# ── Loading ───────────────────────────────────────────────────────────────────


def _read_json(path: Path) -> Optional[Any]:
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            logger.warning("Ignoring oversized review config: %s", path)
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring unreadable review config %s: %s", path, exc)
        return None


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            logger.warning("Ignoring oversized review config: %s", path)
            return ""
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeError) as exc:
        logger.warning("Ignoring unreadable review config %s: %s", path, exc)
        return ""


def _normalize_auto_review(raw: Dict[str, Any], current: List[str]) -> List[str]:
    """Resolve autoReview from its modern and legacy spellings."""
    if isinstance(raw.get("autoReview"), (list, tuple)):
        events = [
            str(event).lower()
            for event in raw["autoReview"]
            if str(event).lower() in REVIEW_TRIGGERS
        ]
        return events
    if "triggerOnUpdates" in raw:
        return list(REVIEW_TRIGGERS) if raw.get("triggerOnUpdates") else ["open"]
    if str(raw.get("skipReview") or "").upper() == "AUTOMATIC":
        return []
    return current


def _apply_raw(
    config: ReviewConfig, raw: Dict[str, Any], source: str = ""
) -> ReviewConfig:
    """Layer one raw config dict onto ``config`` and return the result.

    Scalars from ``raw`` override; rules, context files, prose, and the
    ignore list accumulate so a nested directory can add to — but never
    silently drop — what its parents established.
    """
    if not isinstance(raw, dict):
        return config

    updates: Dict[str, Any] = {}

    if "strictness" in raw:
        try:
            strictness = int(raw["strictness"])
        except (TypeError, ValueError):
            strictness = config.strictness
        updates["strictness"] = min(3, max(1, strictness))

    if isinstance(raw.get("commentTypes"), (list, tuple)):
        types = [
            str(item).lower()
            for item in raw["commentTypes"]
            if str(item).lower() in COMMENT_TYPES
        ]
        updates["comment_types"] = types

    auto_review = _normalize_auto_review(raw, config.auto_review)
    if auto_review != config.auto_review:
        updates["auto_review"] = auto_review

    for key, attr in (
        ("triggerOnDrafts", "trigger_on_drafts"),
        ("shouldUpdateDescription", "should_update_description"),
        ("updateSummaryOnly", "update_summary_only"),
        ("fixWithAI", "fix_with_ai"),
        ("hideFooter", "hide_footer"),
        ("statusCheck", "status_check"),
        ("statusCommentsEnabled", "status_comments_enabled"),
    ):
        if key in raw:
            updates[attr] = bool(raw[key])

    for key, attr in (
        ("labels", "labels"),
        ("disabledLabels", "disabled_labels"),
        ("includeAuthors", "include_authors"),
        ("excludeAuthors", "exclude_authors"),
        ("includeBranches", "include_branches"),
        ("excludeBranches", "exclude_branches"),
        ("includeKeywords", "include_keywords"),
        ("ignoreKeywords", "ignore_keywords"),
    ):
        if key in raw:
            updates[attr] = _split_lines(raw[key])

    if "ignorePatterns" in raw:
        updates["ignore_patterns"] = _union(
            config.ignore_patterns, _split_lines(raw["ignorePatterns"])
        )

    if raw.get("instructions"):
        existing = config.instructions.strip()
        addition = str(raw["instructions"]).strip()
        updates["instructions"] = (
            f"{existing}\n\n{addition}"
            if existing and addition
            else (addition or existing)
        )

    custom_context = (
        raw.get("customContext") if isinstance(raw.get("customContext"), dict) else {}
    )

    new_rules: List[Rule] = []
    for bucket in (raw.get("rules"), custom_context.get("rules")):
        for item in bucket or ():
            rule = Rule.parse(item, source=source)
            if rule:
                new_rules.append(rule)
    for item in custom_context.get("other") or ():
        if isinstance(item, dict) and item.get("content"):
            new_rules.append(
                Rule(
                    rule=str(item["content"]).strip(),
                    scope=_split_lines(item.get("scope")),
                    source=source,
                )
            )
    if new_rules:
        updates["rules"] = config.rules + new_rules

    if "disabledRules" in raw:
        updates["disabled_rules"] = _union(
            config.disabled_rules, _split_lines(raw["disabledRules"])
        )

    new_files: List[ContextFile] = []
    for bucket in (raw.get("files"), custom_context.get("files")):
        for item in bucket or ():
            context_file = ContextFile.parse(item, source=source)
            if context_file:
                new_files.append(context_file)
    if new_files:
        updates["context_files"] = config.context_files + new_files

    if raw.get("prose"):
        updates["prose_rules"] = config.prose_rules + [str(raw["prose"]).strip()]

    context = raw.get("context") if isinstance(raw.get("context"), dict) else {}
    if context.get("repos"):
        updates["context_repos"] = _union(
            config.context_repos, _split_lines(context["repos"])
        )
    if raw.get("patternRepositories"):
        updates["pattern_repositories"] = _union(
            config.pattern_repositories, _split_lines(raw["patternRepositories"])
        )

    for key, attr, default_included in (
        ("summarySection", "summary_section", True),
        ("issuesTableSection", "issues_table_section", True),
        ("confidenceScoreSection", "confidence_score_section", True),
        ("sequenceDiagramSection", "sequence_diagram_section", True),
    ):
        if key in raw:
            updates[attr] = Section.parse(raw[key], default_included)

    if "includeIssuesTable" in raw:
        updates["issues_table_section"] = replace(
            updates.get("issues_table_section", config.issues_table_section),
            included=bool(raw["includeIssuesTable"]),
        )
    if "includeConfidenceScore" in raw:
        updates["confidence_score_section"] = replace(
            updates.get("confidence_score_section", config.confidence_score_section),
            included=bool(raw["includeConfidenceScore"]),
        )
    if "includeSequenceDiagram" in raw:
        updates["sequence_diagram_section"] = replace(
            updates.get("sequence_diagram_section", config.sequence_diagram_section),
            included=bool(raw["includeSequenceDiagram"]),
        )

    if "autoApprove" in raw:
        parsed = AutoApprovePolicy.parse(raw["autoApprove"])
        # The first config to mention autoApprove sets the policy outright;
        # merging it against the (disabled) default would make `enabled: true`
        # impossible to ever express. Nested configs then tighten it.
        updates["auto_approve"] = (
            config.auto_approve.merge(parsed) if config._auto_approve_set else parsed
        )
        updates["_auto_approve_set"] = True

    if source:
        updates["sources"] = _union(config.sources, [source])

    return replace(config, **updates) if updates else config


def _load_config_dir(directory: Path) -> Dict[str, Any]:
    """Read one ``.greptile/`` folder into a single raw config dict."""
    raw: Dict[str, Any] = {}
    config_json = _read_json(directory / "config.json")
    if isinstance(config_json, dict):
        raw.update(config_json)

    files_json = _read_json(directory / "files.json")
    if isinstance(files_json, list):
        raw["files"] = files_json
    elif isinstance(files_json, dict) and isinstance(files_json.get("files"), list):
        raw["files"] = files_json["files"]

    prose = _read_text(directory / "rules.md").strip()
    if prose:
        raw["prose"] = prose
    return raw


def _discover_scoped_configs(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    """Find every non-root ``.greptile/`` folder, keyed by its parent directory."""
    scoped: Dict[str, Dict[str, Any]] = {}
    for dirpath, dirnames, _filenames in os.walk(repo_root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_SCAN_DIRS]
        if CONFIG_DIR not in dirnames:
            continue
        parent = Path(dirpath)
        if parent == repo_root:
            continue  # root config is loaded separately, and always applies
        raw = _load_config_dir(parent / CONFIG_DIR)
        if raw:
            key = str(parent.relative_to(repo_root)).replace(os.sep, "/")
            scoped[key] = raw
    return scoped


def load_review_config(
    repo_root: str, overrides: Optional[Dict[str, Any]] = None
) -> ReviewConfig:
    """Load the effective review config for ``repo_root``.

    Resolution order, each layering onto the last: built-in defaults,
    ``greptile.json``, the root ``.greptile/`` folder (which takes
    precedence), then any explicit ``overrides``. Directory-scoped
    ``.greptile/`` folders are discovered and applied later, per file, by
    :meth:`ReviewConfig.for_path`.
    """
    root = Path(os.path.realpath(os.path.expanduser(repo_root)))
    config = ReviewConfig(repo_root=str(root))

    root_json = _read_json(root / ROOT_CONFIG_FILE)
    if isinstance(root_json, dict):
        config = _apply_raw(config, root_json, source=ROOT_CONFIG_FILE)

    root_dir_raw = _load_config_dir(root / CONFIG_DIR)
    if root_dir_raw:
        config = _apply_raw(config, root_dir_raw, source=f"{CONFIG_DIR}/")

    if overrides:
        config = _apply_raw(config, overrides, source="overrides")

    scoped = _discover_scoped_configs(root) if root.is_dir() else {}
    return replace(config, _scoped=scoped)


__all__ = [
    "COMMENT_TYPES",
    "REVIEW_TRIGGERS",
    "RISK_LEVELS",
    "RULE_SEVERITIES",
    "AutoApprovePolicy",
    "ContextFile",
    "ReviewConfig",
    "Rule",
    "Section",
    "load_review_config",
    "matches_any_glob",
    "matches_glob",
]
