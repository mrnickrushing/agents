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
FALSE_POSITIVE verdict with a one-line reason. It costs an API call per
flagged file (not per project file), so it stays cheap even on a large scan.

Wired into `cli.py scan`: runs automatically whenever ANTHROPIC_API_KEY or
OPENAI_API_KEY is set in the environment, unless overridden with
--triage/--no-triage. No key set → scan behaves exactly as before.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

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
        if not (target == self._project_root or target.startswith(self._project_root + os.sep)):
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
        return {"verdict": "UNKNOWN", "reason": "Triage model did not return a parseable verdict."}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {"verdict": "UNKNOWN", "reason": "Triage model returned malformed JSON."}
    verdict = str(parsed.get("verdict", "UNKNOWN")).upper()
    if verdict not in ("CONFIRMED", "FALSE_POSITIVE"):
        verdict = "UNKNOWN"
    return {"verdict": verdict, "reason": str(parsed.get("reason", ""))}


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


def triage_entry(agent: TriageAgent, project_root: str, entry: Dict[str, Any]) -> Dict[str, str]:
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
    """Run LLM triage over every entry in a `_run_scan` report, adding a
    `triage` key to each entry in place, plus a top-level `triage_summary`.
    Entries where the tool handler itself errored are left alone — there's
    no finding to confirm, just a crash to fix."""
    project_root = os.path.realpath(report["project"])
    agent = TriageAgent(project_root, provider=provider, model=model, api_key=api_key)

    confirmed = 0
    dismissed = 0
    unknown = 0
    for entry in report["results"]:
        if entry["result"].get("error"):
            continue
        entry["triage"] = triage_entry(agent, project_root, entry)
        verdict = entry["triage"]["verdict"]
        if verdict == "CONFIRMED":
            confirmed += 1
        elif verdict == "FALSE_POSITIVE":
            dismissed += 1
        else:
            unknown += 1

    report["triage_summary"] = {
        "confirmed": confirmed,
        "false_positive": dismissed,
        "unknown": unknown,
    }
    return report
