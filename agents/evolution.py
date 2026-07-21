"""Persistent, auditable learning for agent scan findings.

The scanner does not rewrite its own detectors. Instead, it remembers verdicts
for an exact project/file revision, measures those verdicts, and exposes the
evidence needed to improve detectors behind normal tests and code review.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = 1
VALID_VERDICTS = {"CONFIRMED", "FALSE_POSITIVE"}


def default_database_path() -> str:
    override = os.getenv("AGENTS_EVOLUTION_DB")
    if override:
        return os.path.expanduser(override)
    state_root = os.getenv("XDG_STATE_HOME")
    if state_root:
        return os.path.join(
            os.path.expanduser(state_root), "rushingtech-agents", "evolution.db"
        )
    return str(Path.home() / ".local" / "state" / "rushingtech-agents" / "evolution.db")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").split()).casefold()


def _project_identity(project_root: str) -> str:
    root = os.path.realpath(os.path.expanduser(project_root))
    try:
        remote = subprocess.run(
            ["git", "-C", root, "config", "--get", "remote.origin.url"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        repository_prefix = subprocess.run(
            ["git", "-C", root, "rev-parse", "--show-prefix"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        remote = ""
        repository_prefix = ""
    if remote:
        # Avoid allowing embedded HTTPS credentials to become persistent data.
        if "://" in remote and "@" in remote:
            scheme, remainder = remote.split("://", 1)
            remote = f"{scheme}://{remainder.split('@', 1)[1]}"
        identity = remote.removesuffix(".git").casefold()
        # Two independently scanned apps in one monorepo may both contain a
        # src/index.ts. Include the scan root's repo-relative prefix so their
        # finding histories never collide.
        return f"{identity}#{repository_prefix.casefold()}"
    return root


def project_key(project_root: str) -> str:
    return hashlib.sha256(_project_identity(project_root).encode()).hexdigest()[:24]


def _source_hash(project_root: str, relative_path: str) -> str:
    path = os.path.realpath(os.path.join(project_root, relative_path))
    root = os.path.realpath(project_root)
    if not (path == root or path.startswith(root + os.sep)):
        return "outside-project"
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()[:24]
    except OSError:
        return "unavailable"


def _finding_rows(
    report: Dict[str, Any],
) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for entry in report.get("results", []):
        findings = entry.get("result", {}).get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                yield entry, finding


def attach_finding_ids(report: Dict[str, Any]) -> Dict[str, Any]:
    """Attach stable IDs that change whenever the reviewed source changes."""
    root = os.path.realpath(report["project"])
    pkey = project_key(root)
    occurrences: Dict[str, int] = {}
    for entry, finding in _finding_rows(report):
        relative_path = str(entry.get("file", "")).replace(os.sep, "/")
        source_hash = str(entry.get("source_hash") or _source_hash(root, relative_path))
        identity = "\x1f".join(
            [
                pkey,
                str(entry.get("agent", "")),
                str(entry.get("tool", "")),
                relative_path,
                _normalized_text(finding.get("severity")),
                _normalized_text(finding.get("issue")),
                _normalized_text(finding.get("fix")),
                source_hash,
            ]
        )
        occurrence = occurrences.get(identity, 0)
        occurrences[identity] = occurrence + 1
        digest = hashlib.sha256(f"{identity}\x1f{occurrence}".encode()).hexdigest()[:20]
        finding["finding_id"] = f"agf_{digest}"
    report["project_key"] = pkey
    return report


class EvolutionStore:
    def __init__(self, database_path: Optional[str] = None) -> None:
        self.database_path = database_path or default_database_path()
        if self.database_path != ":memory:":
            os.makedirs(
                os.path.dirname(os.path.abspath(self.database_path)), exist_ok=True
            )
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self._migrate()

    def __enter__(self) -> "EvolutionStore":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                scan_id TEXT PRIMARY KEY,
                project_key TEXT NOT NULL,
                project_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                detector_version TEXT NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scan_runs_project_idx
                ON scan_runs(project_key, created_at DESC);
            CREATE TABLE IF NOT EXISTS findings (
                scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
                finding_id TEXT NOT NULL,
                project_key TEXT NOT NULL,
                file TEXT NOT NULL,
                agent TEXT NOT NULL,
                tool TEXT NOT NULL,
                severity TEXT NOT NULL,
                issue TEXT NOT NULL,
                fix TEXT NOT NULL,
                PRIMARY KEY (scan_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS findings_id_idx ON findings(finding_id);
            CREATE TABLE IF NOT EXISTS feedback (
                feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                project_key TEXT NOT NULL,
                verdict TEXT NOT NULL CHECK (verdict IN ('CONFIRMED', 'FALSE_POSITIVE')),
                reason TEXT NOT NULL,
                source TEXT NOT NULL CHECK (source IN ('human', 'triage')),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS feedback_finding_idx
                ON feedback(finding_id, source, created_at DESC);
            """)
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.connection.commit()

    def _latest_feedback(self, finding_id: str) -> Optional[sqlite3.Row]:
        return self.connection.execute(
            """
            SELECT verdict, reason, source, created_at
            FROM feedback
            WHERE finding_id = ?
            ORDER BY CASE source WHEN 'human' THEN 0 ELSE 1 END,
                     created_at DESC, feedback_id DESC
            LIMIT 1
            """,
            (finding_id,),
        ).fetchone()

    def apply_feedback(self, report: Dict[str, Any]) -> Dict[str, Any]:
        attach_finding_ids(report)
        learned = 0
        for entry in report.get("results", []):
            verdicts: List[Dict[str, str]] = []
            for finding in entry.get("result", {}).get("findings", []):
                row = self._latest_feedback(finding["finding_id"])
                if not row:
                    continue
                feedback = dict(row)
                finding["feedback"] = feedback
                verdicts.append(feedback)
                learned += 1
            if verdicts:
                if any(item["verdict"] == "CONFIRMED" for item in verdicts):
                    verdict = "CONFIRMED"
                elif all(item["verdict"] == "FALSE_POSITIVE" for item in verdicts):
                    verdict = "FALSE_POSITIVE"
                else:
                    verdict = "UNKNOWN"
                entry["feedback"] = {
                    "verdict": verdict,
                    "reason": "; ".join(
                        item["reason"] for item in verdicts if item["reason"]
                    ),
                    "source": "persisted",
                }
        report["evolution"] = {"learned_verdicts_applied": learned}
        return report

    def record_scan(self, report: Dict[str, Any], detector_version: str) -> str:
        attach_finding_ids(report)
        scan_id = f"ags_{uuid.uuid4().hex[:20]}"
        created_at = _utc_now()
        report["scan_id"] = scan_id
        report.setdefault("evolution", {})["database"] = self.database_path
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO scan_runs(scan_id, project_key, project_path, created_at, detector_version, report_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    report["project_key"],
                    report["project"],
                    created_at,
                    detector_version,
                    json.dumps(report, default=str),
                ),
            )
            for entry, finding in _finding_rows(report):
                self.connection.execute(
                    """
                    INSERT INTO findings(
                        scan_id, finding_id, project_key, file, agent, tool, severity, issue, fix
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding["finding_id"],
                        report["project_key"],
                        entry.get("file", ""),
                        entry.get("agent", ""),
                        entry.get("tool", ""),
                        finding.get("severity", "INFO"),
                        finding.get("issue", ""),
                        finding.get("fix", ""),
                    ),
                )
                triage = finding.get("triage")
                if triage and triage.get("verdict") in VALID_VERDICTS:
                    self.connection.execute(
                        """
                        INSERT INTO feedback(finding_id, project_key, verdict, reason, source, created_at)
                        VALUES (?, ?, ?, ?, 'triage', ?)
                        """,
                        (
                            finding["finding_id"],
                            report["project_key"],
                            triage["verdict"],
                            triage.get("reason", ""),
                            created_at,
                        ),
                    )
        return scan_id

    def add_feedback(
        self, finding_id: str, verdict: str, reason: str
    ) -> Dict[str, str]:
        verdict = verdict.upper()
        aliases = {"CONFIRM": "CONFIRMED", "DISMISS": "FALSE_POSITIVE"}
        verdict = aliases.get(verdict, verdict)
        if verdict not in VALID_VERDICTS:
            raise ValueError(
                "verdict must be confirm/CONFIRMED or dismiss/FALSE_POSITIVE"
            )
        finding = self.connection.execute(
            """
            SELECT finding_id, project_key, file, agent, tool, issue
            FROM findings WHERE finding_id = ? ORDER BY rowid DESC LIMIT 1
            """,
            (finding_id,),
        ).fetchone()
        if not finding:
            raise KeyError(f"Unknown finding ID: {finding_id}")
        created_at = _utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO feedback(finding_id, project_key, verdict, reason, source, created_at)
                VALUES (?, ?, ?, ?, 'human', ?)
                """,
                (finding_id, finding["project_key"], verdict, reason, created_at),
            )
        return {
            "finding_id": finding_id,
            "verdict": verdict,
            "reason": reason,
            "file": finding["file"],
            "detector": f"{finding['agent']}.{finding['tool']}",
        }

    def recent_runs(
        self, project: Optional[str] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where = ""
        if project:
            where = "WHERE r.project_key = ?"
            params.append(project_key(project))
        params.append(limit)
        rows = self.connection.execute(
            f"""
            SELECT r.scan_id, r.project_path, r.created_at, r.detector_version,
                   COUNT(f.finding_id) AS findings
            FROM scan_runs r LEFT JOIN findings f ON f.scan_id = r.scan_id
            {where}
            GROUP BY r.scan_id
            ORDER BY r.created_at DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def evaluate(self, project: Optional[str] = None) -> Dict[str, Any]:
        params: List[Any] = []
        where = ""
        if project:
            where = "WHERE f.project_key = ?"
            params.append(project_key(project))
        human_rows = self.connection.execute(
            f"""
            WITH latest_human AS (
                SELECT fb.*, ROW_NUMBER() OVER (
                    PARTITION BY finding_id ORDER BY created_at DESC, feedback_id DESC
                ) AS rank
                FROM feedback fb WHERE source = 'human'
            )
            SELECT f.finding_id, f.agent, f.tool, h.verdict
            FROM findings f
            JOIN latest_human h ON h.finding_id = f.finding_id AND h.rank = 1
            {where}
            GROUP BY f.finding_id
            """,
            params,
        ).fetchall()
        confirmed = sum(row["verdict"] == "CONFIRMED" for row in human_rows)
        dismissed = sum(row["verdict"] == "FALSE_POSITIVE" for row in human_rows)
        labeled = confirmed + dismissed

        detector_counts: Dict[str, Dict[str, Any]] = {}
        for row in human_rows:
            key = f"{row['agent']}.{row['tool']}"
            counts = detector_counts.setdefault(
                key, {"confirmed": 0, "false_positive": 0}
            )
            counts[
                "confirmed" if row["verdict"] == "CONFIRMED" else "false_positive"
            ] += 1
        for counts in detector_counts.values():
            total = counts["confirmed"] + counts["false_positive"]
            counts["actionable_precision"] = round(counts["confirmed"] / total, 4)

        agreement_params: List[Any] = []
        agreement_where = ""
        if project:
            agreement_where = "AND h.project_key = ?"
            agreement_params.append(project_key(project))
        agreement_rows = self.connection.execute(
            f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY finding_id, source ORDER BY created_at DESC, feedback_id DESC
                ) AS rank
                FROM feedback
            )
            SELECT h.verdict AS human_verdict, t.verdict AS triage_verdict
            FROM ranked h JOIN ranked t ON t.finding_id = h.finding_id
            WHERE h.source = 'human' AND h.rank = 1
              AND t.source = 'triage' AND t.rank = 1 {agreement_where}
            """,
            agreement_params,
        ).fetchall()
        agreements = sum(
            row["human_verdict"] == row["triage_verdict"] for row in agreement_rows
        )

        return {
            "labeled_findings": labeled,
            "confirmed": confirmed,
            "false_positive": dismissed,
            "actionable_precision": round(confirmed / labeled, 4) if labeled else None,
            "triage_comparisons": len(agreement_rows),
            "triage_agreement": (
                round(agreements / len(agreement_rows), 4) if agreement_rows else None
            ),
            "detectors": detector_counts,
            "recall": None,
            "recall_note": "Recall needs labeled clean files or known missed findings; scan feedback alone cannot measure it.",
        }
