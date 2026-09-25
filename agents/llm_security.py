"""
LLM Security Agent — auditing the code that calls a model.

Covers the risks that only exist once an application hands work to an LLM,
following the OWASP Top 10 for LLM Applications: untrusted input reaching the
instruction channel (LLM01 Prompt Injection), uncapped spend (Unbounded
Consumption, the "denial of wallet" case), model output reaching a dangerous
sink (Improper Output Handling), keys shipped to the client, and tools the
model can call that execute whatever arguments it chooses.

Every check is deterministic and needs no API key::

    from agents import LLMSecurityAgent
    agent = LLMSecurityAgent()
    findings = agent._audit_prompt_construction(code=source)["findings"]

Precision note that shapes this whole module: passing user input *to* a model
is the entire point of a chat feature, so "user text reaches the model" is not
a finding. What these checks look for is user text reaching the part of the
request the application is supposed to control — the system prompt, the tool
list, the spend ceiling — or model output reaching a sink that executes it.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent

# ── Shared vocabulary ─────────────────────────────────────────────────────────

#: Calls that hand a request to a model. Kept broad on purpose — each handler
#: re-decides on the call's own arguments, so a loose match costs a regex, not
#: a false positive.
_LLM_CALL_RE = re.compile(
    r"\b(?:"
    r"chat\.completions\.create|completions\.create|responses\.create"
    r"|messages\.create|messages\.stream"
    r"|generateText|streamText|generateObject|streamObject"
    r"|\.invoke|\.predict|\.generate_content|\.chat\b"
    r"|ollama\.(?:chat|generate)|litellm\.completion"
    r")\s*\(",
    re.IGNORECASE,
)

#: A file is only worth auditing when it actually talks to a model.
_LLM_CONTEXT_RE = re.compile(
    r"\b(?:openai|anthropic|claude|gpt-[0-9]|litellm|ollama|langchain"
    r"|@ai-sdk|vercel/ai|bedrock|gemini|generativeai)\b",
    re.IGNORECASE,
)

#: Values that originate outside the process.
_UNTRUSTED_RE = re.compile(
    r"\b(?:req|request)\.(?:body|params|query|args|form|json|values|data)"
    r"|\brequest\.(?:query_params|path_params)"
    r"|\b(?:user_?input|user_?message|user_?prompt|user_?query|user_?text)\b"
    r"|\bsearchParams\b|\bformData\b",
    re.IGNORECASE,
)


def _balanced_call(text: str, open_paren: int) -> str:
    """Return one balanced call, ignoring parentheses inside quoted text."""
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren : index + 1]
    return text[open_paren:]


def _llm_calls(code: str) -> List[str]:
    """Every model call in ``code``, method name and balanced arguments.

    The name has to travel with the arguments: which SDK is being called
    decides whether an absent token cap is a spend risk or simply a request
    the API will reject, and the argument list alone does not say.
    """
    calls: List[str] = []
    for match in _LLM_CALL_RE.finditer(code):
        arguments = _balanced_call(code, match.end() - 1)
        calls.append(code[match.start() : match.end() - 1] + arguments)
    return calls


def _talks_to_a_model(code: str) -> bool:
    return bool(_LLM_CONTEXT_RE.search(code) or _LLM_CALL_RE.search(code))


def _line_of(code: str, index: int) -> int:
    return code[:index].count("\n") + 1


def _finding(severity: str, issue: str, fix: str, **extra: Any) -> Dict[str, Any]:
    finding = {"severity": severity, "issue": issue, "fix": fix}
    finding.update({key: value for key, value in extra.items() if value})
    return finding


# ── LLM01: untrusted input in the instruction channel ─────────────────────────

#: A system/instruction message — the part of the request the app owns.
#: The key may itself be quoted — `"role": "system"` is the common spelling,
#: and requiring `role` to sit directly against the colon missed all of it.
_SYSTEM_ROLE_RE = re.compile(
    r"""["']?\brole["']?\s*[:=]\s*["']system["']""", re.IGNORECASE
)

#: Kwargs and variable names that carry instructions rather than user turns.
_INSTRUCTION_SLOT_RE = re.compile(
    r"""["']?\b(?:system|system_?prompt|system_?message|instructions|preamble)"""
    r"""["']?\s*[:=]\s*""",
    re.IGNORECASE,
)

#: Splicing, as opposed to passing a value through as its own argument.
_INTERPOLATION_RE = re.compile(
    r"""f["'`][^\n]*\{|\$\{|["']\s*\+\s*\w|\.format\s*\(|["']\s*%\s*[(\w]|\.join\s*\("""
)


def _enclosing_object(code: str, position: int) -> Optional[str]:
    """The object literal containing ``position``, or None if not inside one."""
    depth = 0
    start = -1
    for index in range(position, -1, -1):
        char = code[index]
        if char == "}":
            depth += 1
        elif char == "{":
            if depth == 0:
                start = index
                break
            depth -= 1
    if start == -1:
        return None

    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return code[start : index + 1]
    return code[start:]


def _value_after(code: str, position: int) -> str:
    """The value assigned at ``position``, stopping at the next argument.

    Bounded by the expression itself rather than a fixed character count. A
    fixed window ran past the end of a static system message and into the next
    statement, so a nearby `logger.info(f"{req.body.message}")` was reported as
    prompt injection even though the request value never entered the prompt.
    """
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index in range(position, len(code)):
        char = code[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return code[position:index]
            depth -= 1
        elif char in ",\n" and depth == 0:
            return code[position:index]
    return code[position:]


def _instruction_windows(code: str) -> List[tuple]:
    """Spans of code that build a system/instruction message.

    Each window is the instruction *value* — the message object for a
    `role: "system"` entry, or the assigned expression for a `system=` kwarg —
    never a fixed slice of surrounding source.
    """
    windows: List[tuple] = []
    for match in _SYSTEM_ROLE_RE.finditer(code):
        window = _enclosing_object(code, match.start())
        windows.append((match.start(), window or _value_after(code, match.end())))
    for match in _INSTRUCTION_SLOT_RE.finditer(code):
        windows.append((match.start(), _value_after(code, match.end())))
    return windows


def _audit_prompt_construction_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not _talks_to_a_model(code):
        return findings

    for start, window in _instruction_windows(code):
        # Stop at the next role boundary so a user message following a static
        # system message cannot be read as part of it — that user message
        # holding untrusted input is correct usage, not a finding.
        boundary = re.search(
            r"""["']?\brole["']?\s*[:=]\s*["'](?:user|assistant|tool)["']""",
            window,
            re.IGNORECASE,
        )
        if boundary:
            window = window[: boundary.start()]
        if not _INTERPOLATION_RE.search(window):
            continue
        if not _UNTRUSTED_RE.search(window):
            continue
        findings.append(
            _finding(
                "CRITICAL",
                "Untrusted input is spliced into the system prompt — prompt injection",
                "Keep the system prompt a constant and pass the user's text as its own "
                "user-role message, so the model's instructions cannot be overwritten "
                "by what the user types.",
                line=_line_of(code, start),
                evidence=window.strip().splitlines()[0][:160],
            )
        )
        break  # one report per file is enough to act on

    return findings


# ── Unbounded consumption: the denial-of-wallet case ──────────────────────────

_TOKEN_CAP_RE = re.compile(
    r"\bmax_?(?:tokens|completion_tokens|output_tokens|new_tokens)\b", re.IGNORECASE
)
_TIMEOUT_RE = re.compile(r"\btimeout\b|\bsignal\s*[:=]|AbortSignal", re.IGNORECASE)
_UNBOUNDED_LOOP_RE = re.compile(r"\bwhile\s+(?:True|true|1)\s*[:{)]")

#: SDKs whose API requires a cap, so an absent one fails before it bills.
_REQUIRES_CAP_RE = re.compile(r"messages\.(?:create|stream)", re.IGNORECASE)

#: A timeout set where it covers every call the client goes on to make.
_CLIENT_TIMEOUT_RE = re.compile(
    r"(?:OpenAI|Anthropic|AsyncOpenAI|AsyncAnthropic|Client)\s*\([^)]*\btimeout\b"
    r"|with_options\s*\([^)]*\btimeout\b"
    r"|\bdefault_?[Tt]imeout\b",
    re.IGNORECASE,
)


def _audit_token_limits_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    calls = _llm_calls(code)
    if not calls:
        return findings

    # Anthropic's messages.create rejects a request with no max_tokens before
    # any output is generated or billed, so an absent cap there is an API error
    # rather than a spend risk — reporting it would contradict this agent's own
    # guidance and bury the calls that really are uncapped.
    uncapped = [
        call
        for call in calls
        if not _TOKEN_CAP_RE.search(call) and not _REQUIRES_CAP_RE.search(call)
    ]
    if uncapped:
        findings.append(
            _finding(
                "MEDIUM",
                f"{len(uncapped)} model call(s) set no output token cap — "
                "a long generation bills to you with nothing to stop it",
                "Pass max_tokens (max_completion_tokens / maxOutputTokens depending on "
                "the SDK) on every call, sized to what the feature actually needs.",
                evidence=uncapped[0][:160],
            )
        )

    # A timeout on the client constructor covers every call it makes; a bare
    # `timeout` anywhere in the file does not, and scanning the whole file for
    # one let genuinely unbounded calls through.
    untimed = [call for call in calls if not _TIMEOUT_RE.search(call)]
    if untimed and not _CLIENT_TIMEOUT_RE.search(code):
        findings.append(
            _finding(
                "LOW",
                "Model calls set no timeout — a stalled upstream holds the request open",
                "Set an explicit timeout on the client or per call, and fail the request "
                "rather than waiting indefinitely.",
                evidence=untimed[0][:160],
            )
        )

    # A model call inside `while True` with no visible break is a bill with no
    # ceiling, which is a different and worse problem than one uncapped call.
    for match in _UNBOUNDED_LOOP_RE.finditer(code):
        body = code[match.end() : match.end() + 900]
        if _LLM_CALL_RE.search(body) and not re.search(r"\bbreak\b|\breturn\b", body):
            findings.append(
                _finding(
                    "HIGH",
                    "Model call inside an unbounded loop with no visible exit — "
                    "spend is limited only by how long the process runs",
                    "Bound the loop with a maximum iteration or token budget and break "
                    "when it is reached.",
                    line=_line_of(code, match.start()),
                )
            )
            break

    return findings


# ── Keys that reach the client ────────────────────────────────────────────────

#: Build-time prefixes that inline a value into the shipped bundle.
_PUBLIC_ENV_RE = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|PUBLIC|NUXT_PUBLIC|GATSBY)_"
    r"[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|LLM|AI)"
    r"[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b"
)

#: The prefix alone matched `api_key="sk-ant-..."` in a docstring example, so a
#: long random tail is required — that is what separates a key from a placeholder.
_LITERAL_KEY_RE = re.compile(
    r"""["'](?:sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}"""
    r"""|sk-[A-Za-z0-9]{32,})"""
)


def _audit_llm_key_exposure_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    if re.search(r"dangerouslyAllowBrowser\s*:\s*true", code):
        findings.append(
            _finding(
                "CRITICAL",
                "LLM client constructed with dangerouslyAllowBrowser: true — "
                "the API key ships to every visitor",
                "Call the model from a server route or edge function and keep the key "
                "server-side. The flag exists to make this hard to do by accident.",
            )
        )

    public = _PUBLIC_ENV_RE.search(code)
    if public:
        findings.append(
            _finding(
                "CRITICAL",
                f"LLM API key read from `{public.group(0)}` — that prefix inlines the "
                "value into the client bundle",
                "Move the key to a server-only variable (no public prefix) and proxy the "
                "model call through your backend.",
                line=_line_of(code, public.start()),
            )
        )

    literal = _LITERAL_KEY_RE.search(code)
    if literal:
        findings.append(
            _finding(
                "CRITICAL",
                "Hardcoded LLM API key literal in source",
                "Read the key from the environment and rotate the exposed one — it is in "
                "git history from the moment it was committed.",
                line=_line_of(code, literal.start()),
            )
        )

    return findings


# ── Improper output handling ──────────────────────────────────────────────────

_ASSIGNED_CALL_RE = re.compile(
    r"(?:const|let|var)?\s*(?P<name>\w+)\s*=\s*(?:await\s+)?[\w.]*?"
    r"(?:chat\.completions\.create|messages\.create|generateText|generateObject"
    r"|completions\.create|responses\.create|\.invoke|litellm\.completion)\s*\(",
    re.IGNORECASE,
)

#: Sinks that execute or render whatever they are handed.
_SINKS = (
    (r"\.innerHTML\s*\+?=", "rendered as HTML", "CRITICAL"),
    (r"dangerouslySetInnerHTML", "rendered as HTML", "CRITICAL"),
    (r"\beval\s*\(", "evaluated as code", "CRITICAL"),
    (
        r"\bexec\s*\(|\bexecSync\s*\(|child_process|subprocess\.",
        "run as a shell command",
        "CRITICAL",
    ),
    (r"\bnew\s+Function\s*\(", "compiled as a function", "CRITICAL"),
    (r"\bos\.system\s*\(", "run as a shell command", "CRITICAL"),
)


def _audit_llm_output_handling_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    names = {match.group("name") for match in _ASSIGNED_CALL_RE.finditer(code)}
    if not names:
        return findings

    for name in sorted(names):
        for pattern, verb, severity in _SINKS:
            for match in re.finditer(pattern, code):
                # The sink has to actually receive this response. Look at the
                # statement it sits in rather than the whole file, so an
                # unrelated eval elsewhere does not get blamed on the model.
                line_start = code.rfind("\n", 0, match.start()) + 1
                line_end = code.find("\n", match.end())
                statement = code[line_start : line_end if line_end != -1 else len(code)]
                if re.search(rf"\b{re.escape(name)}\b", statement):
                    findings.append(
                        _finding(
                            severity,
                            f"Model output (`{name}`) is {verb} without sanitisation — "
                            "anything that steers the model now steers your app",
                            "Treat model output as untrusted input: validate it against a "
                            "schema, and render as text rather than HTML or code.",
                            line=_line_of(code, match.start()),
                            evidence=statement.strip()[:160],
                        )
                    )
                    return findings  # one is enough to act on

    return findings


# ── Tools the model can call ──────────────────────────────────────────────────

_TOOL_DEF_RE = re.compile(
    r"\btools\s*[:=]\s*\[|\bfunction_call\b|\btool_choice\b|@tool\b"
    r"|\"type\"\s*:\s*\"function\"|'type'\s*:\s*'function'",
    re.IGNORECASE,
)

_DANGEROUS_EXECUTOR_RE = re.compile(
    r"\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_output)\s*\("
    r"|\bexecSync\s*\(|\bspawnSync\s*\(|child_process"
    r"|\beval\s*\(|\bexec\s*\("
    r"|\b(?:unlink|rmdir|rmtree|remove)\s*\("
)


def _audit_llm_tool_exposure_impl(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not _TOOL_DEF_RE.search(code) or not _talks_to_a_model(code):
        return findings

    executor = _DANGEROUS_EXECUTOR_RE.search(code)
    if not executor:
        return findings

    # A validated executor is the point of a tool-using agent; an unvalidated
    # one hands the shell to whoever can talk to the model.
    validated = re.search(
        r"\ballow(?:ed|list)\b|\bwhitelist\b|\bshlex\.quote\b|\bschema\b"
        r"|\bvalidate\w*\s*\(|\bsafeParse\b|\bz\.\w+\s*\(|\bpydantic\b",
        code,
        re.IGNORECASE,
    )
    findings.append(
        _finding(
            "HIGH" if not validated else "MEDIUM",
            "A model-callable tool reaches a shell/filesystem executor"
            + ("" if validated else " with no visible argument validation"),
            "Validate every tool argument against a strict schema and an allowlist "
            "before it reaches the executor. The model chooses these values, and "
            "anything that can talk to the model chooses them too.",
            line=_line_of(code, executor.start()),
            evidence=executor.group(0),
        )
    )
    return findings


# ── Agent ─────────────────────────────────────────────────────────────────────


class LLMSecurityAgent(BaseAgent):
    """Audits application code that calls a language model."""

    name = "llm_security"
    description = (
        "Audits code that calls an LLM — prompt injection through the system "
        "prompt, uncapped token spend, API keys reaching the client bundle, "
        "model output reaching a dangerous sink, and model-callable tools that "
        "execute unvalidated arguments."
    )
    model = "gpt-5"

    system_prompt = """\
You review the code around a language model, not the model itself.

The risks that matter here exist only once an application delegates work to an \
LLM:

- Untrusted text reaching the instruction channel. Passing what a user typed to \
a model is the point of the feature; splicing it into the system prompt is the \
vulnerability, because the model cannot tell the two apart.
- Spend with no ceiling. A call with no token cap and no timeout bills to the \
operator for as long as the model keeps going.
- Keys in the bundle. A public build prefix or dangerouslyAllowBrowser puts the \
key in every visitor's browser.
- Output treated as trusted. Model output rendered as HTML or executed as code \
means anything that steers the model steers the app.
- Tools with unvalidated arguments. The model chooses those arguments, and so \
does anyone who can talk to the model.

Report a concrete path: the input, where it lands, and what it does there. \
"Consider sanitising" is not a finding; "user input from req.body is \
interpolated into the system prompt at line 40, so a user can replace the \
instructions" is.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        code_param = {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        }
        return [
            {
                "name": "audit_prompt_construction",
                "description": (
                    "Detects untrusted input spliced into the system prompt or "
                    "instruction slot, where it can override the app's instructions."
                ),
                "parameters": code_param,
            },
            {
                "name": "audit_token_limits",
                "description": (
                    "Detects model calls with no output token cap or timeout, and "
                    "calls inside unbounded loops — the denial-of-wallet cases."
                ),
                "parameters": code_param,
            },
            {
                "name": "audit_llm_key_exposure",
                "description": (
                    "Detects LLM API keys reaching the client: public build prefixes, "
                    "dangerouslyAllowBrowser, and hardcoded key literals."
                ),
                "parameters": code_param,
            },
            {
                "name": "audit_llm_output_handling",
                "description": (
                    "Detects model output reaching a sink that renders or executes it "
                    "without validation."
                ),
                "parameters": code_param,
            },
            {
                "name": "audit_llm_tool_exposure",
                "description": (
                    "Detects model-callable tools whose arguments reach a shell, "
                    "filesystem, or eval executor without validation."
                ),
                "parameters": code_param,
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "audit_prompt_construction": self._audit_prompt_construction,
            "audit_token_limits": self._audit_token_limits,
            "audit_llm_key_exposure": self._audit_llm_key_exposure,
            "audit_llm_output_handling": self._audit_llm_output_handling,
            "audit_llm_tool_exposure": self._audit_llm_tool_exposure,
        }

    def _audit_prompt_construction(self, code: str) -> Dict[str, Any]:
        findings = _audit_prompt_construction_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_token_limits(self, code: str) -> Dict[str, Any]:
        findings = _audit_token_limits_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_llm_key_exposure(self, code: str) -> Dict[str, Any]:
        findings = _audit_llm_key_exposure_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_llm_output_handling(self, code: str) -> Dict[str, Any]:
        findings = _audit_llm_output_handling_impl(code)
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_llm_tool_exposure(self, code: str) -> Dict[str, Any]:
        findings = _audit_llm_tool_exposure_impl(code)
        return {"findings": findings, "total_issues": len(findings)}


__all__ = ["LLMSecurityAgent"]
