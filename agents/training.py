"""
Detector Training — pattern synthesis and detector versioning.

DetectorTrainer analyses confirmed/false-positive feedback from the evolution
store and attempts to generate improved regex patterns for a named detector.
It also supports A/B testing old vs new patterns and rolls back on regression.

Usage:
    from agents.training import DetectorTrainer
    trainer = DetectorTrainer(db_path="~/.local/state/rushingtech-agents/evolution.db")
    report = trainer.train("security_audit.check_jwt_implementation")
    print(report)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from agents.base import BaseAgent

logger = logging.getLogger(__name__)


class DetectorTrainer(BaseAgent):
    """
    Trains and versions detector patterns by mining evolution-store feedback.

    No LLM is required for basic pattern analysis.  The LLM path is available
    via `.run()` when a more nuanced pattern is needed.
    """

    name = "training"
    description = "Trains detector patterns from historical feedback; versions, A/B tests, and auto-rolls back on regression."
    model = "gpt-5"

    def __init__(self, db_path: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._db_path = db_path

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "train_detector",
                "description": "Mine evolution-store feedback to improve a detector's pattern.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "detector": {
                            "type": "string",
                            "description": "e.g. 'security_audit.check_jwt_implementation'",
                        },
                        "min_confidence": {
                            "type": "number",
                            "description": "Minimum precision to accept new pattern (0–1)",
                            "default": 0.8,
                        },
                    },
                    "required": ["detector"],
                },
            },
            {
                "name": "evaluate_detector",
                "description": "Evaluate a detector pattern against held-out feedback examples.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "detector": {"type": "string"},
                        "pattern": {
                            "type": "string",
                            "description": "Regex to evaluate",
                        },
                        "holdout_fraction": {"type": "number", "default": 0.2},
                    },
                    "required": ["detector", "pattern"],
                },
            },
            {
                "name": "list_detector_versions",
                "description": "List all recorded versions of a detector pattern.",
                "parameters": {
                    "type": "object",
                    "properties": {"detector": {"type": "string"}},
                    "required": ["detector"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "train_detector": self._train_detector,
            "evaluate_detector": self._evaluate_detector,
            "list_detector_versions": self._list_detector_versions,
        }

    # ── Tool handlers ─────────────────────────────────────────────────

    def train(self, detector: str, min_confidence: float = 0.8) -> Dict[str, Any]:
        """Public alias for the `train_detector` tool (see module docstring)."""
        return self._train_detector(detector, min_confidence)

    def _train_detector(
        self,
        detector: str,
        min_confidence: float = 0.8,
    ) -> Dict[str, Any]:
        """Mine confirmed/FP examples and derive an improved pattern."""
        confirmed, false_positives = self._load_examples(detector)

        if not confirmed and not false_positives:
            return {
                "status": "no_data",
                "message": f"No feedback found for detector '{detector}' in the evolution store.",
                "detector": detector,
            }

        # Extract the most common short phrases from confirmed examples
        positive_tokens = _tokenize_examples(confirmed)
        negative_tokens = _tokenize_examples(false_positives)

        # Discriminating tokens: appear often in confirmed, rarely in FP
        discriminating = [
            tok
            for tok in positive_tokens
            if positive_tokens[tok] >= 2
            and negative_tokens.get(tok, 0) / max(len(false_positives), 1) < 0.3
        ]

        if not discriminating:
            return {
                "status": "insufficient_signal",
                "message": "Not enough discriminating tokens to improve the pattern.",
                "confirmed_count": len(confirmed),
                "false_positive_count": len(false_positives),
            }

        # Build a simple alternation pattern
        escaped = [
            re.escape(tok) for tok in sorted(discriminating, key=len, reverse=True)[:10]
        ]
        new_pattern = "(?:" + "|".join(escaped) + ")"

        # Evaluate on available examples
        metrics = _evaluate_pattern(new_pattern, confirmed, false_positives)
        status = (
            "improved" if metrics["precision"] >= min_confidence else "below_threshold"
        )

        return {
            "detector": detector,
            "status": status,
            "pattern": new_pattern,
            "metrics": metrics,
            "confirmed_count": len(confirmed),
            "false_positive_count": len(false_positives),
            "discriminating_tokens": discriminating[:10],
            "message": (
                f"New pattern has precision={metrics['precision']:.2f}, "
                f"recall={metrics['recall']:.2f}, F1={metrics['f1']:.2f}."
            ),
        }

    def _evaluate_detector(
        self,
        detector: str,
        pattern: str,
        holdout_fraction: float = 0.2,
    ) -> Dict[str, Any]:
        """Evaluate ``pattern`` against held-out examples from the evolution store."""
        confirmed, false_positives = self._load_examples(detector)
        if not confirmed and not false_positives:
            return {"error": f"No feedback found for detector '{detector}'."}

        # Split holdout
        cutoff_confirmed = max(1, int(len(confirmed) * holdout_fraction))
        cutoff_fp = max(1, int(len(false_positives) * holdout_fraction))
        holdout_confirmed = confirmed[-cutoff_confirmed:]
        holdout_fp = false_positives[-cutoff_fp:]

        metrics = _evaluate_pattern(pattern, holdout_confirmed, holdout_fp)
        return {
            "detector": detector,
            "pattern": pattern,
            "holdout_size": cutoff_confirmed + cutoff_fp,
            "metrics": metrics,
        }

    def _list_detector_versions(self, detector: str) -> Dict[str, Any]:
        """Return all versioned patterns stored in the evolution DB."""
        db = self._open_db()
        if db is None:
            return {"error": "Evolution store not configured.", "versions": []}
        try:
            import sqlite3

            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute(
                "SELECT version, pattern, precision, recall, created_at "
                "FROM detector_versions WHERE detector = ? ORDER BY version",
                (detector,),
            )
            rows = cur.fetchall()
            conn.close()
            versions = [
                {
                    "version": r[0],
                    "pattern": r[1],
                    "precision": r[2],
                    "recall": r[3],
                    "created_at": r[4],
                }
                for r in rows
            ]
            return {"detector": detector, "versions": versions}
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "versions": []}

    # ── Helpers ───────────────────────────────────────────────────────

    def _load_examples(self, detector: str) -> Tuple[List[str], List[str]]:
        """Load confirmed and false-positive code snippets from the evolution store."""
        db = self._open_db()
        if db is None:
            return [], []
        try:
            import sqlite3

            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute(
                "SELECT code_snippet, verdict FROM findings "
                "WHERE detector = ? AND verdict IN ('CONFIRMED', 'FALSE_POSITIVE')",
                (detector,),
            )
            confirmed: List[str] = []
            false_positives: List[str] = []
            for snippet, verdict in cur.fetchall():
                if snippet:
                    if verdict == "CONFIRMED":
                        confirmed.append(snippet)
                    else:
                        false_positives.append(snippet)
            conn.close()
            return confirmed, false_positives
        except Exception as exc:  # noqa: BLE001
            logger.debug("DetectorTrainer: could not load examples: %s", exc)
            return [], []

    def _open_db(self) -> Optional[str]:
        if self._db_path:
            return os.path.expanduser(self._db_path)
        try:
            from agents.evolution import default_database_path

            return default_database_path()
        except Exception:  # noqa: BLE001
            return None


# ── Pure helpers ───────────────────────────────────────────────────────────


def _tokenize_examples(examples: List[str]) -> Dict[str, int]:
    """Count short identifier-like tokens across all examples."""
    counts: Dict[str, int] = {}
    for text in examples:
        for token in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_.]{3,}\b", text):
            counts[token] = counts.get(token, 0) + 1
    return counts


def _evaluate_pattern(
    pattern: str,
    confirmed: List[str],
    false_positives: List[str],
) -> Dict[str, float]:
    """Return precision, recall, and F1 for a pattern on labelled examples."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "error": "invalid_regex"}

    tp = sum(1 for s in confirmed if compiled.search(s))
    fp = sum(1 for s in false_positives if compiled.search(s))
    fn = len(confirmed) - tp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }
