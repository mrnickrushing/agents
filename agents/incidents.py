"""Failure fingerprinting — turn a CI/deploy log into a stable signature.

The point is institutional memory. A solo operator running twenty projects
re-diagnoses the same class of failure over and over: the same Trivy sarif
gate, the same pytest sys.path problem, the same peer-dependency conflict,
rediscovered from scratch in each repo months apart. Nothing remembers.

A signature has to satisfy two opposing requirements:

* **Stable** across the noise that differs every run — timestamps, runner
  paths, commit hashes, durations, line numbers, versions — so the *same*
  failure in a different repo six weeks later still matches.
* **Specific** enough that two genuinely different failures don't collide,
  because a false match sends you down the wrong path with false confidence,
  which is worse than no memory at all.

The approach: keep only the lines that look like errors, aggressively
normalize the parts that vary, dedupe, and hash a bounded number of them.
Bounded because a log that dumps fifty stack frames should still match the
same failure that dumped forty — the head of the error is the identity.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Tuple

# How many distinct normalized error lines make up a signature. Small enough
# that trailing noise doesn't perturb it, large enough to stay specific.
SIGNATURE_LINES = 5

# Lines worth considering. Deliberately broad — a missed error line costs a
# non-match (silent), while an extra benign line is usually normalized away.
_ERROR_LINE = re.compile(
    r"(error|fail(ed|ure|s)?|fatal|traceback|exception|cannot|could not|unable|"
    r"not found|denied|refused|timeout|timed out|unsupported|invalid|conflict|"
    r"##\[error\]|npm err|exit code|non-zero)",
    re.IGNORECASE,
)

# Applied in order. Order matters: hashes before numbers, or a hex string
# gets shredded into <n> fragments first.
_SCRUB: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\x1b\[[0-9;]*[a-zA-Z]"), ""),                    # ANSI colour
    (re.compile(r"^\s*\d{4}-\d{2}-\d{2}t[\d:.]+z?\s*", re.I), ""),  # leading ISO ts
    (re.compile(r"##\[(error|warning|group|endgroup)\]", re.I), ""),
    (re.compile(r"\b[0-9a-f]{7,64}\b", re.I), "<hash>"),           # sha/commit/uuid-ish
    (re.compile(r"\bv?\d+\.\d+(\.\d+)*([-+][0-9a-z.]+)?\b", re.I), "<ver>"),
    (re.compile(r"(/[\w.@+-]+){2,}/?"), "<path>"),                 # unix-ish paths
    (re.compile(r"\b[a-z]:\\[\w\\.@+-]+", re.I), "<path>"),        # windows paths
    (re.compile(r"\b\d+\b"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def normalize_line(line: str) -> str:
    """Strip everything that legitimately differs between two runs of the
    same failure, leaving the shape of the error.
    """
    text = line.strip().lower()
    for pattern, repl in _SCRUB:
        text = pattern.sub(repl, text)
    return text.strip()


def salient_lines(log: str, limit: int = SIGNATURE_LINES) -> List[str]:
    """The normalized error lines that define this failure, in order, deduped."""
    seen: set[str] = set()
    out: List[str] = []
    for raw in log.splitlines():
        if not _ERROR_LINE.search(raw):
            continue
        norm = normalize_line(raw)
        # A line that normalized down to punctuation/placeholders carries no
        # signal — matching on it would collide unrelated failures.
        if len(norm) < 12 or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
        if len(out) >= limit:
            break
    return out


def fingerprint(log: str) -> Tuple[str, List[str]]:
    """(signature, the normalized lines it was built from).

    Returning the lines matters as much as the hash: a match you can't
    inspect is a match you can't trust, and this is meant to be shown to a
    human deciding whether the suggested fix actually applies.
    """
    lines = salient_lines(log)
    if not lines:
        # No recognizable error text. Hash the whole thing so the caller still
        # gets a usable key, but it will only ever match a byte-identical log.
        digest = hashlib.sha256(normalize_line(log).encode("utf-8")).hexdigest()
        return digest[:32], []
    joined = "\n".join(lines)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32], lines
