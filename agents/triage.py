"""
LLM triage — a second pass over `agents.cli scan` findings.

`scan` runs pure regex/heuristic checks against one file at a time, with no
LLM and no API key. That's what makes it fast and free, but it also means it
can't tell "this file doesn't set a token's expiration" from "this file only
verifies a token whose expiration is enforced somewhere else" — it has no way
to look outside the one file it's looking at, and a real project audited this
way runs heavily false-positive (an Apple Sign-In nonce/JWKS check split
across a client file and a server file, flagged as missing in both, is a
typical example).

Triage re-examines each flagged finding with an actual model — via a
`TriageAgent` that can call a `read_project_file` tool to pull in whatever
other files would settle the question — and asks it for a CONFIRMED /
FALSE_POSITIVE verdict with a one-line reason. Each finding gets an independent
verdict, so one valid bug does not keep unrelated noise from the same file.

Wired into `cli.py scan`: runs automatically whenever ANTHROPIC_API_KEY or
OPENAI_API_KEY is set in the environment, unless overridden with
--triage/--no-triage. No key set → scan behaves exactly as before.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agents.base import BaseAgent

MAX_TRIAGE_FILE_BYTES = 40_000

TRIAGE_SYSTEM_PROMPT = """You are a precise senior engineer verifying findings produced by a \
regex-based static-analysis scanner. Each finding names a specific issue in a specific file. \
The scanner has no understanding of the rest of the codebase — it cannot tell whether the real \
logic lives in a different file, whether the concern is already handled by another layer, or \
whether the pattern it matched has nothing to do with what it's warning about.

You have a `read_project_file` tool that reads any other file in the project by a path relative \
to the project root. Use it whenever the finding could plausibly be explained, contradicted, or \
already handled by code elsewhere — for example, a file that only verifies a token doesn't need \
to set that token's expiration; that's a different file's job, and you should go check whether \
that other file does it correctly before deciding. Don't guess about code you haven't read.

Once you've verified enough to decide, respond with ONLY a JSON object, no markdown fences and no \
other text, of the form:
{"verdict": "CONFIRMED", "reason": "<one or two sentences, cite the file that proves it>"}
or
{"verdict": "FALSE_POSITIVE", "reason": "<one or two sentences, cite the file that proves it>"}

CONFIRMED means the finding describes a real, unaddressed gap after you've checked the places \
where it could plausibly be handled. FALSE_POSITIVE means the underlying concern is actually \
addressed — in this file or another — or the pattern matched something that isn't what it claims."""


def _read_project_file_tool_schema() -> Dict[str, Any]:
    return {
        "name": "read_project_file",
        "description": "Read a file's contents by path relative to the project root.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to the project root, e.g. 'apps/api/app/security.py'",
                },
            },
            "required": ["path"],
        },
    }


class TriageAgent(BaseAgent):
    name = "triage"
    description = "Confirms or dismisses static-analysis findings by reading related project files."
    system_prompt = TRIAGE_SYSTEM_PROMPT
    max_tool_rounds = 6

    def __init__(self, project_root: str, **kwargs: Any) -> None:
        self._project_root = os.path.realpath(project_root)
        super().__init__(**kwargs)

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [_read_project_file_tool_schema()]

    def _bind_tool_handlers(self) -> Dict[str, Any]:
        return {"read_project_file": self._read_project_file}

    def _read_project_file(self, path: str) -> Dict[str, Any]:
        # Resolve and confine to the project root so the model can't be
        # steered (by its own mistake or a crafted finding) into reading
        # anything outside the scanned project, e.g. via a `../../` path.
        target = os.path.realpath(os.path.join(self._project_root, path))
        if not (
            target == self._project_root
            or target.startswith(self._project_root + os.sep)
        ):
            return {"error": "Path escapes project root"}
        if not os.path.isfile(target):
            return {"error": f"No such file: {path}"}
        try:
            with open(target, "r", errors="ignore") as fh:
                content = fh.read(MAX_TRIAGE_FILE_BYTES)
        except OSError as e:
            return {"error": str(e)}
        return {"path": path, "content": content}


def _extract_verdict(text: str) -> Dict[str, str]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {
            "verdict": "UNKNOWN",
            "reason": "Triage model did not return a parseable verdict.",
        }
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {"verdict": "UNKNOWN", "reason": "Triage model returned malformed JSON."}
    verdict = str(parsed.get("verdict", "UNKNOWN")).upper()
    if verdict not in ("CONFIRMED", "FALSE_POSITIVE"):
        verdict = "UNKNOWN"
    return {"verdict": verdict, "reason": str(parsed.get("reason", ""))}


def _extract_verdicts(text: str, count: int) -> List[Dict[str, str]]:
    """Parse a batched response: one verdict object per finding, in order.

    Anything short of `count` well-formed verdicts degrades to UNKNOWN for
    the missing ones rather than shifting later verdicts onto earlier
    findings — a misaligned verdict is worse than no verdict, because it
    silently teaches the scorer the opposite of the truth.
    """
    unknown = {"verdict": "UNKNOWN", "reason": "No verdict returned for this finding."}
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return [dict(unknown) for _ in range(count)]
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return [
            {"verdict": "UNKNOWN", "reason": "Triage model returned malformed JSON."}
            for _ in range(count)
        ]
    if not isinstance(parsed, list):
        return [dict(unknown) for _ in range(count)]

    by_index: Dict[int, Dict[str, str]] = {}
    for position, item in enumerate(parsed):
        if not isinstance(item, dict):
            continue
        # Prefer an explicit index; fall back to position. The model is asked
        # for indexes precisely so a dropped item cannot shift the rest.
        try:
            index = int(item.get("index", position))
        except (TypeError, ValueError):
            index = position
        verdict = str(item.get("verdict", "UNKNOWN")).upper()
        if verdict not in ("CONFIRMED", "FALSE_POSITIVE"):
            verdict = "UNKNOWN"
        by_index[index] = {"verdict": verdict, "reason": str(item.get("reason", ""))}
    return [by_index.get(i, dict(unknown)) for i in range(count)]


def triage_entry_findings(
    agent: "TriageAgent", project_root: str, entry: Dict[str, Any]
) -> List[Dict[str, str]]:
    """One verdict per finding in `entry`, using a single model call.

    The per-finding loop this replaces re-sent the whole file for every
    finding in it — a 14-finding component uploaded its own source fourteen
    times. Findings from one entry share a file and a rule by construction,
    so judging them together is both cheaper and better informed: the model
    sees the whole picture once instead of fourteen keyhole views.
    """
    findings = _findings_of(entry)
    if not findings:
        return []

    file_path = entry["file"]
    abs_path = os.path.join(project_root, file_path)
    try:
        with open(abs_path, "r", errors="ignore") as fh:
            file_content = fh.read(MAX_TRIAGE_FILE_BYTES)
    except OSError:
        file_content = "<could not read file>"

    numbered = "\n".join(
        f"[{i}] {f.get('severity', 'INFO')}: {f.get('issue', f.get('message', ''))}"
        + (f" (line {f['line']})" if f.get("line") else "")
        for i, f in enumerate(findings)
    )

    prompt = f"""Tool: {entry['agent']}.{entry['tool']}
File: {file_path}

Findings reported by the scanner, each with an index:
{numbered}

Contents of {file_path}:
```
{file_content}
```

Verify EACH finding independently. Read other project files if the real
answer could live elsewhere. Judge every finding on its own merits — they
share a file, not a fate.

Respond with a JSON array only, one object per finding, each with:
  "index"   the finding's index above
  "verdict" either "CONFIRMED" or "FALSE_POSITIVE"
  "reason"  one sentence
Return exactly {len(findings)} objects, including every index."""

    conversation_id = f"{file_path}:{entry['tool']}"
    try:
        response = agent.run(prompt, conversation_id=conversation_id)
    finally:
        # A verdict is a one-shot judgement, not a dialogue. BaseAgent
        # accumulates history per conversation_id, so without this every
        # later call on the same file+tool re-sends the whole previous
        # exchange — the file included. The old per-finding loop shared one
        # id across all of a file's findings and paid 1+2+...+N copies of
        # that file: a 27-finding entry sent 378 copies of one source file.
        # Batching removed the common case; this removes the rest, and stops
        # the agent holding every file it has read in memory for the run.
        agent.reset(conversation_id)
    return _extract_verdicts(response.content, len(findings))


async def triage_entry_findings_async(
    agent: "TriageAgent", project_root: str, entry: Dict[str, Any]
) -> List[Dict[str, str]]:
    findings = _findings_of(entry)
    if not findings:
        return []

    file_path = entry["file"]
    abs_path = os.path.join(project_root, file_path)
    try:
        with open(abs_path, "r", errors="ignore") as fh:
            file_content = fh.read(MAX_TRIAGE_FILE_BYTES)
    except OSError:
        file_content = "<could not read file>"

    numbered = "\n".join(
        f"[{i}] {f.get('severity', 'INFO')}: {f.get('issue', f.get('message', ''))}"
        + (f" (line {f['line']})" if f.get("line") else "")
        for i, f in enumerate(findings)
    )
    prompt = f"""Tool: {entry['agent']}.{entry['tool']}
File: {file_path}

Findings reported by the scanner, each with an index:
{numbered}

Contents of {file_path}:
```
{file_content}
```

Verify EACH finding independently. Read other project files if the real
answer could live elsewhere. Judge every finding on its own merits — they
share a file, not a fate.

Respond with a JSON array only, one object per finding, each with:
  "index"   the finding's index above
  "verdict" either "CONFIRMED" or "FALSE_POSITIVE"
  "reason"  one sentence
Return exactly {len(findings)} objects, including every index."""

    conversation_id = f"{file_path}:{entry['tool']}"
    try:
        response = await agent.run_async(prompt, conversation_id=conversation_id)
    finally:
        agent.reset(conversation_id)
    return _extract_verdicts(response.content, len(findings))


def _findings_of(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = entry["result"]
    findings = (
        result.get("findings")
        or result.get("jwt_findings")
        or result.get("cors_findings")
        or result.get("diagnoses")
        or result.get("recommendations")
        or []
    )
    return [f for f in findings if isinstance(f, dict)]


def _finding_summary(entry: Dict[str, Any]) -> str:
    lines = []
    for f in _findings_of(entry):
        line = f"- [{f.get('severity', 'INFO')}] {f.get('issue', '')}"
        if f.get("fix"):
            line += f"\n  fix: {f['fix']}"
        lines.append(line)
    return "\n".join(lines)


def triage_entry(
    agent: TriageAgent, project_root: str, entry: Dict[str, Any]
) -> Dict[str, str]:
    """Ask the triage agent to confirm or dismiss one scan entry (a file +
    the tool that flagged it — may bundle several individual findings)."""
    file_path = entry["file"]
    abs_path = os.path.join(project_root, file_path)
    try:
        with open(abs_path, "r", errors="ignore") as fh:
            file_content = fh.read(MAX_TRIAGE_FILE_BYTES)
    except OSError:
        file_content = "<could not read file>"

    prompt = f"""Tool: {entry['agent']}.{entry['tool']}
File: {file_path}

Findings reported by the scanner:
{_finding_summary(entry)}

Contents of {file_path}:
```
{file_content}
```

Verify these findings. Read other project files if the real answer could live elsewhere.
Respond with the JSON verdict only."""

    response = agent.run(prompt, conversation_id=f"{file_path}:{entry['tool']}")
    return _extract_verdict(response.content)


def triage_report(
    report: Dict[str, Any],
    provider: str = "anthropic",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Run LLM triage over every individual finding in a `_run_scan` report,
    then derive an entry verdict without letting one valid finding keep an
    unrelated false positive alive (or vice versa).
    Entries where the tool handler itself errored are left alone — there's
    no finding to confirm, just a crash to fix."""
    project_root = os.path.realpath(report["project"])
    agent = TriageAgent(project_root, provider=provider, model=model, api_key=api_key)
    rag = TriageRAG(project_root=project_root)

    confirmed = 0
    dismissed = 0
    unknown = 0
    for entry in report["results"]:
        if entry["result"].get("error"):
            continue
        findings = _findings_of(entry)
        # One call per entry, not per finding: every finding here shares this
        # file, and the old loop re-uploaded it once per finding.
        contexts = []
        for finding in findings:
            contexts.append(
                rag.retrieve_context(
                    {
                        "agent": entry.get("agent", ""),
                        "rule": entry.get("tool", ""),
                        "file": entry.get("file", ""),
                        "issue": finding.get("issue", ""),
                    }
                )
            )
        if contexts and all(
            c["total_similar"] >= 3 and c["confidence"] >= 0.75 for c in contexts
        ):
            verdicts = [
                {
                    "verdict": c["majority_verdict"],
                    "reason": f"RAG cache: {c['confidence'] * 100:.0f}% agreement across {c['total_similar']} similar findings.",
                }
                for c in contexts
            ]
        else:
            verdicts = triage_entry_findings(agent, project_root, entry)
        for finding, triage in zip(findings, verdicts):
            finding["triage"] = triage
            if triage["verdict"] == "CONFIRMED":
                confirmed += 1
            elif triage["verdict"] == "FALSE_POSITIVE":
                dismissed += 1
            else:
                unknown += 1
            if triage["verdict"] in {"CONFIRMED", "FALSE_POSITIVE"}:
                rag.record_verdict(
                    {
                        "agent": entry.get("agent", ""),
                        "rule": entry.get("tool", ""),
                        "file": entry.get("file", ""),
                        "issue": finding.get("issue", ""),
                    },
                    triage["verdict"],
                    triage.get("reason", ""),
                )

        if verdicts:
            if any(v["verdict"] == "CONFIRMED" for v in verdicts):
                entry_verdict = "CONFIRMED"
            elif all(v["verdict"] == "FALSE_POSITIVE" for v in verdicts):
                entry_verdict = "FALSE_POSITIVE"
            else:
                entry_verdict = "UNKNOWN"
            reasons = "; ".join(v["reason"] for v in verdicts if v.get("reason"))
            entry["triage"] = {"verdict": entry_verdict, "reason": reasons}

    rag.close()
    report["triage_summary"] = {
        "confirmed": confirmed,
        "false_positive": dismissed,
        "unknown": unknown,
    }
    coverage = report.get("coverage")
    if isinstance(coverage, dict):
        if coverage.get("tool_errors") or coverage.get("skipped_files") or unknown:
            coverage["confidence"] = "incomplete"
        else:
            coverage["confidence"] = "heuristics-triaged-runtime-unverified"
    return report


async def triage_report_async(
    report: Dict[str, Any],
    provider: str = "anthropic",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    project_root = os.path.realpath(report["project"])
    agent = TriageAgent(project_root, provider=provider, model=model, api_key=api_key)

    async def process_entry(
        entry: Dict[str, Any],
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, str]]] | None:
        if entry["result"].get("error"):
            return None
        findings = _findings_of(entry)
        verdicts = await triage_entry_findings_async(agent, project_root, entry)
        return entry, findings, verdicts

    confirmed = 0
    dismissed = 0
    unknown = 0
    try:
        processed = await asyncio.gather(
            *(process_entry(entry) for entry in report["results"])
        )
        for item in processed:
            if item is None:
                continue
            entry, findings, verdicts = item
            for finding, triage in zip(findings, verdicts):
                finding["triage"] = triage
                if triage["verdict"] == "CONFIRMED":
                    confirmed += 1
                elif triage["verdict"] == "FALSE_POSITIVE":
                    dismissed += 1
                else:
                    unknown += 1
            if verdicts:
                if any(v["verdict"] == "CONFIRMED" for v in verdicts):
                    entry_verdict = "CONFIRMED"
                elif all(v["verdict"] == "FALSE_POSITIVE" for v in verdicts):
                    entry_verdict = "FALSE_POSITIVE"
                else:
                    entry_verdict = "UNKNOWN"
                reasons = "; ".join(v["reason"] for v in verdicts if v.get("reason"))
                entry["triage"] = {"verdict": entry_verdict, "reason": reasons}
    finally:
        await agent.aclose()

    report["triage_summary"] = {
        "confirmed": confirmed,
        "false_positive": dismissed,
        "unknown": unknown,
    }
    coverage = report.get("coverage")
    if isinstance(coverage, dict):
        if coverage.get("tool_errors") or coverage.get("skipped_files") or unknown:
            coverage["confidence"] = "incomplete"
        else:
            coverage["confidence"] = "heuristics-triaged-runtime-unverified"
    return report


# ── TriageRAG — RAG-enhanced triage with historical context ───────────────────

_RAG_SCHEMA = """
CREATE TABLE IF NOT EXISTS rag_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint    TEXT    NOT NULL UNIQUE,
    agent          TEXT,
    rule           TEXT,
    file           TEXT,
    issue          TEXT,
    verdict        TEXT,
    reason         TEXT,
    embedding_json TEXT,
    created_at     REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rag_rule   ON rag_findings(rule);
CREATE INDEX IF NOT EXISTS idx_rag_agent  ON rag_findings(agent);
CREATE INDEX IF NOT EXISTS idx_rag_verdict ON rag_findings(verdict);
"""

_DEFAULT_RAG_DB = Path.home() / ".rushingtech" / "evolution.db"


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Stable fingerprint for a finding, used as the primary de-dup key."""
    key = json.dumps(
        {
            "agent": finding.get("agent", ""),
            "rule": finding.get("rule", ""),
            "file": finding.get("file", ""),
            "issue": finding.get("issue", ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()


def _simple_embed(text: str, dim: int = 64) -> List[float]:
    """
    Lightweight pseudo-embedding (no ML library required).

    Hashes trigrams of the normalised text into a fixed-size float vector.
    Cosine similarity between these vectors tracks lexical overlap reasonably
    well for our use-case (same rule + same file type) without requiring
    sentence-transformers or any external dependency.
    """
    text = re.sub(r"\W+", " ", text.lower()).strip()
    tokens = text.split()
    vec = [0.0] * dim
    for i, tok in enumerate(tokens):
        for ch in tok:
            idx = (ord(ch) * (i + 1) * 31) % dim
            vec[idx] += 1.0
    # L2-normalise
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _finding_text(finding: Dict[str, Any]) -> str:
    """Human-readable text representation of a finding for embedding."""
    parts = [
        finding.get("agent", ""),
        finding.get("rule", ""),
        os.path.basename(finding.get("file", "")),
        finding.get("issue", ""),
    ]
    return " ".join(p for p in parts if p)


class TriageRAG:
    """
    Retrieval-Augmented Generation helper for triage.

    Stores past finding verdicts in SQLite and retrieves the most similar
    historical findings as context for the LLM triage prompt.  This allows
    the triage agent to reason about patterns it has seen before:

        "We've seen this rule fire 12 times before.  10 were CONFIRMED,
         2 were FALSE_POSITIVE (both in test directories)."

    Usage::

        rag = TriageRAG(project_root="/path/to/project")

        # Retrieve context for a new finding
        context = rag.retrieve_context(finding)

        # After triage, record the verdict so future scans benefit
        rag.record_verdict(finding, verdict="CONFIRMED", reason="...")

        # Full RAG-enhanced triage (requires TriageAgent)
        result = await rag.triage_with_rag(agent, finding, min_confidence=0.75)
    """

    def __init__(
        self,
        project_root: str = ".",
        db_path: Optional[str] = None,
        min_similarity: float = 0.5,
        top_k: int = 5,
    ) -> None:
        self._project_root = os.path.realpath(project_root)
        self._min_similarity = min_similarity
        self._top_k = top_k
        _path = Path(db_path) if db_path else _DEFAULT_RAG_DB
        _path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_RAG_SCHEMA)
        self._conn.commit()

    # ── record ────────────────────────────────────────────────────────

    def record_verdict(
        self,
        finding: Dict[str, Any],
        verdict: str,
        reason: str = "",
    ) -> None:
        """Persist a triage verdict so future scans can learn from it."""
        fp = _finding_fingerprint(finding)
        embedding = _simple_embed(_finding_text(finding))
        self._conn.execute(
            """
            INSERT INTO rag_findings
                (fingerprint, agent, rule, file, issue, verdict, reason, embedding_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                verdict        = excluded.verdict,
                reason         = excluded.reason,
                embedding_json = excluded.embedding_json
            """,
            (
                fp,
                finding.get("agent", ""),
                finding.get("rule", ""),
                finding.get("file", ""),
                finding.get("issue", ""),
                verdict.upper(),
                reason,
                json.dumps(embedding),
                time.time(),
            ),
        )
        self._conn.commit()

    # ── retrieve ──────────────────────────────────────────────────────

    def retrieve_context(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve similar past findings and compute a confidence score.

        Returns a dict with:
        - ``similar``: list of the top-K past findings (sorted by similarity)
        - ``confirmed_count``: how many were CONFIRMED
        - ``false_positive_count``: how many were FALSE_POSITIVE
        - ``confidence``: float 0–1 (fraction that were CONFIRMED)
        - ``context_text``: formatted string suitable for injection into an LLM prompt
        """
        embedding = _simple_embed(_finding_text(finding))

        # Pull candidates by same rule first (fast); fall back to all if sparse
        rows = self._conn.execute(
            "SELECT fingerprint, agent, rule, file, issue, verdict, reason, embedding_json "
            "FROM rag_findings WHERE rule = ?",
            (finding.get("rule", ""),),
        ).fetchall()

        if len(rows) < 20:
            # Broaden to same agent
            rows = self._conn.execute(
                "SELECT fingerprint, agent, rule, file, issue, verdict, reason, embedding_json "
                "FROM rag_findings WHERE agent = ?",
                (finding.get("agent", ""),),
            ).fetchall()

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for row in rows:
            try:
                row_emb = json.loads(row["embedding_json"] or "[]")
            except (json.JSONDecodeError, TypeError):
                row_emb = []
            if not row_emb:
                continue
            sim = _cosine(embedding, row_emb)
            if sim >= self._min_similarity:
                scored.append((sim, dict(row)))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = [item for _, item in scored[: self._top_k]]

        confirmed = sum(1 for t in top if t["verdict"] == "CONFIRMED")
        fp_count = sum(1 for t in top if t["verdict"] == "FALSE_POSITIVE")
        total = len(top)
        majority_verdict = "UNKNOWN"
        majority_count = 0
        if confirmed > fp_count:
            majority_verdict, majority_count = "CONFIRMED", confirmed
        elif fp_count > confirmed:
            majority_verdict, majority_count = "FALSE_POSITIVE", fp_count
        confidence = (majority_count / total) if total > 0 else 0.0

        lines = []
        for item in top:
            lines.append(
                f"- {item['verdict']}: {item['issue']} in {os.path.basename(item['file'] or '')} "
                f"— {item['reason'] or 'no reason recorded'}"
            )
        context_text = "\n".join(lines) if lines else "No similar past findings."

        return {
            "similar": top,
            "confirmed_count": confirmed,
            "false_positive_count": fp_count,
            "total_similar": total,
            "confidence": confidence,
            "majority_verdict": majority_verdict,
            "context_text": context_text,
        }

    # ── triage_with_rag ───────────────────────────────────────────────

    async def triage_with_rag(
        self,
        agent: "TriageAgent",
        finding: Dict[str, Any],
        min_confidence: float = 0.75,
    ) -> Dict[str, Any]:
        """
        Run an LLM triage pass enhanced with historical RAG context.

        If ``min_confidence`` is met (enough historical agreement), the
        historical verdict is returned directly without an LLM call.

        Returns::

            {
                "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "UNKNOWN",
                "confidence": 0.92,
                "reason": "...",
                "similar": [...],
                "source": "rag_cache" | "llm",
            }
        """
        ctx = self.retrieve_context(finding)

        # Fast path: high-confidence historical verdict
        if ctx["total_similar"] >= 3 and ctx["confidence"] >= min_confidence:
            verdict = ctx["majority_verdict"]
            reason = (
                f"RAG: the {verdict} verdict has {ctx['confidence'] * 100:.0f}% agreement "
                f"across {ctx['total_similar']} similar past findings."
            )
            return {
                "verdict": verdict,
                "confidence": ctx["confidence"],
                "reason": reason,
                "similar": ctx["similar"],
                "source": "rag_cache",
            }

        # Low confidence: call low-FP path: pass context into a synthetic
        # "entry" and run the standard triage with additional historical note
        file_path = finding.get("file", "")
        abs_path = os.path.join(self._project_root, file_path) if file_path else ""
        file_content = "<could not read file>"
        if abs_path and os.path.isfile(abs_path):
            try:
                with open(abs_path, "r", errors="ignore") as fh:
                    file_content = fh.read(MAX_TRIAGE_FILE_BYTES)
            except OSError:
                pass

        history_block = ctx["context_text"]
        prompt = (
            f"Finding: {finding.get('issue', '')} in {file_path}\n"
            f"Severity: {finding.get('severity', 'UNKNOWN')}\n\n"
            f"Historical context (similar past findings):\n{history_block}\n\n"
            f"File contents:\n```\n{file_content}\n```\n\n"
            "Respond with ONLY a JSON object:\n"
            '{"verdict": "CONFIRMED" or "FALSE_POSITIVE", "reason": "<one sentence>"}'
        )

        conversation_id = f"rag:{_finding_fingerprint(finding)}"
        try:
            response = await agent.run_async(prompt, conversation_id=conversation_id)
        finally:
            agent.reset(conversation_id)

        verdict_obj = _extract_verdict(response.content)
        return {
            "verdict": verdict_obj["verdict"],
            "confidence": ctx["confidence"],
            "reason": verdict_obj["reason"],
            "similar": ctx["similar"],
            "source": "llm",
        }

    def record_report_verdicts(self, report: Dict[str, Any]) -> int:
        """
        Bulk-record all triaged findings from a completed triage report.

        Call this after ``triage_report()`` to populate the RAG store for
        future scans.  Returns the number of records written.
        """
        written = 0
        for entry in report.get("results", []):
            agent_name = entry.get("agent", "")
            rule = entry.get("tool", "")
            file_path = entry.get("file", "")
            for finding in _findings_of(entry):
                triage = finding.get("triage")
                if not isinstance(triage, dict):
                    continue
                verdict = triage.get("verdict", "UNKNOWN")
                if verdict not in ("CONFIRMED", "FALSE_POSITIVE"):
                    continue
                self.record_verdict(
                    {
                        "agent": agent_name,
                        "rule": rule,
                        "file": file_path,
                        "issue": finding.get("issue", ""),
                    },
                    verdict=verdict,
                    reason=triage.get("reason", ""),
                )
                written += 1
        return written

    def close(self) -> None:
        self._conn.close()
