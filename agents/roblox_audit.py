"""
Roblox Audit Agent — server authority, remotes, DataStore, and Rojo project
structure review for Roblox/Luau games.

Every other agent in this project assumes a web/mobile stack (Express,
FastAPI, Expo). Roblox games have their own exploit surface — the client
runs untrusted Lua that can call any exposed RemoteEvent/RemoteFunction with
arbitrary arguments, and a Rojo project.json mapping can accidentally ship
server-only source into a client-replicated container where any exploiter can
read it. Those are the two highest-severity, most Roblox-specific mistakes;
DataStore/receipt/performance/connection-leak checks round out the rest.

Usage:
    from agents import RobloxAuditAgent
    agent = RobloxAuditAgent(api_key="sk-...")
    result = agent.run("Review this RemoteEvent handler")
    print(result.content)
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent
from agents.luau_static import analyze_repository

_DATASTORE_WRITE_METHODS = ("SetAsync", "UpdateAsync", "IncrementAsync", "RemoveAsync")
_DATASTORE_METHODS = ("GetAsync",) + _DATASTORE_WRITE_METHODS

_LUAU_BLOCK_TOKEN_RE = re.compile(r"\b(function|do|if|repeat|end|until)\b")
_FRAME_SIGNAL_RE = re.compile(r"[.:]\s*(?:Heartbeat|Stepped|RenderStepped)\s*:\s*Connect\s*\(")
# A Luau if-*expression* ("local x = if a then b else c") has no closing
# `end` — only a preceding statement-position keyword means the `if` we're
# looking at is the block-form ("if a then ... end") that actually needs one.
_IF_EXPRESSION_CONTEXT_RE = re.compile(r"(?:=|\(|,|\breturn\b|\band\b|\bor\b|\bnot\b)\s*$")


def _strip_luau_noise(code: str) -> str:
    """Blank out comments/string bodies so keyword-based block matching
    doesn't trip over "end"/"do" appearing inside a comment or string.

    String literals are collapsed to an empty literal (`""`/`''`) rather than
    deleted outright — some checks (a hardcoded-name comparison, a literal
    argument to FindFirstChild) need to know a quoted literal is *present*,
    just not what's inside it.
    """
    text = re.sub(r"--\[(=*)\[.*?\]\1\]", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.DOTALL)
    text = re.sub(r"--[^\n]*", "", text)
    text = re.sub(r"\[(=*)\[.*?\]\1\]", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    text = re.sub(r"([\"'])(?:\\.|(?!\1).)*\1", lambda m: m.group(1) * 2, text)
    return text


def _block_end(stripped: str, after: int) -> int:
    """Return the index just past the `end`/`until` that closes the block
    whose opening `do`/`if`/`function`/`repeat` occurs at or before `after`.

    A fixed-size character window (the simpler alternative) misjudges Lua
    block boundaries — a loop's `do ... end` can be shorter or longer than
    any fixed guess, silently missing real nested code or, worse, pulling in
    unrelated code that runs *after* the block as if it were still inside it.
    Walking real `do`/`if`/`function`/`repeat`/`end`/`until` tokens with a
    stack gets the actual boundary regardless of body length. `elseif`/
    `else`/`then` are deliberately not tracked: they belong to the enclosing
    `if` and never require an extra `end` of their own.
    """
    stack = ["end"]
    for match in _LUAU_BLOCK_TOKEN_RE.finditer(stripped, after):
        token = match.group(1)
        if token == "if" and _IF_EXPRESSION_CONTEXT_RE.search(stripped, 0, match.start()):
            continue
        if token in ("function", "do", "if"):
            stack.append("end")
        elif token == "repeat":
            stack.append("until")
        elif token == "end":
            if stack and stack[-1] == "end":
                stack.pop()
        elif token == "until":
            if stack and stack[-1] == "until":
                stack.pop()
        if not stack:
            return match.end()
    return len(stripped)


def _matching_paren_end(text: str, after_open: int) -> int:
    """Return the index just past the `)` that matches the `(` immediately
    before `after_open` (depth already at 1). Used to find the real extent
    of a `pcall(...)`/`xpcall(...)` call — whatever sits inside those parens,
    whether a `function() ... end` literal or a bare argument list, counts as
    protected, regardless of how far away it is textually."""
    depth = 1
    i = after_open
    length = len(text)
    while i < length and depth > 0:
        char = text[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        i += 1
    return i


_HANDLER_ENTRY_RE = re.compile(r"OnServerEvent\s*:\s*Connect\s*\(\s*function\s*\(\s*(\w+)")
_HANDLER_INVOKE_RE = re.compile(r"OnServerInvoke\s*=\s*function\s*\(\s*(\w+)")


def _iter_remote_handlers(stripped: str):
    """Yield (trusted_player_param, body) for every OnServerEvent/
    OnServerInvoke handler in already-noise-stripped source, with `body`
    bounded to that handler's real closing `end` via `_block_end` rather
    than a guessed window."""
    matches = list(_HANDLER_ENTRY_RE.finditer(stripped)) + list(_HANDLER_INVOKE_RE.finditer(stripped))
    for match in matches:
        trusted_param = match.group(1)
        body_end = _block_end(stripped, match.end())
        yield trusted_param, stripped[match.end() : body_end]


# Roblox service names that are downloaded to and readable by every client.
# A Rojo tree node under one of these is client-visible; server-only source
# mapped underneath it ships implementation (and any embedded secrets/logic)
# straight to exploiters.
_CLIENT_VISIBLE_SERVICES = {
    "ReplicatedStorage",
    "ReplicatedFirst",
    "StarterPlayer",
    "StarterGui",
    "StarterPack",
    "Workspace",
}
_SERVER_SOURCE_HINTS = ("server", "serverscriptservice", "serverstorage")

_TEXT_FILTER_INDICATOR_RE = re.compile(
    r"FilterStringAsync|FilterStringForBroadcast|GetNonChatStringForBroadcastAsync"
    r"|GetNonChatStringForUserAsync|GetChatForUserAsync|TextChatService"
)
_TEXTUAL_ARG_NAME_RE = re.compile(r"(?i)\b\w*(?:text|msg|message|chat|content)\w*\b")
_BROADCAST_CALL_RE = re.compile(r":\s*(?:FireAllClients|FireClient)\s*\(")

_ADMIN_KEYWORDS_RE = re.compile(
    r"(?i)\badmin\b|\bowner\b|\bmoderator\b|\bkick\s*\(|:\s*Kick\s*\(|\bban\b|setrank"
    r"|\bgod\b|invincib|\binfinite\b|giveall|grantall|unlockall|\bshutdown\b"
)
_IDENTITY_STRING_COMPARE_RE = re.compile(r"\.\s*(Name|DisplayName)\s*==\s*[\"']")


class RobloxAuditAgent(BaseAgent):
    """
    Roblox/Luau specialist: remote validation, server authority, DataStore
    safety, Rojo project structure, connection leaks, receipt processing,
    text filtering, and admin-backdoor detection.
    """

    name = "roblox_audit"
    description = (
        "Reviews Roblox/Luau code for remote-event trust boundaries, server authority, "
        "DataStore safety and request-budget usage, Rojo project structure, connection leaks, "
        "MarketplaceService receipt processing, text-filtering gaps, and admin-backdoor patterns."
    )
    model = "gpt-5"

    system_prompt = """\
You are a Roblox game security and reliability specialist reviewing Luau source and Rojo
project configuration for solo/small-team Roblox developers.

YOUR DOMAIN:

1. REMOTE TRUST BOUNDARY
   - The server is the only trust boundary a Roblox game has. Every RemoteEvent.OnServerEvent
     and RemoteFunction.OnServerInvoke handler must treat every argument except the
     engine-supplied `player` parameter as attacker-controlled.
   - The first parameter Roblox passes to OnServerEvent/OnServerInvoke is the real sending
     player and cannot be spoofed by an exploit. A handler that instead resolves "which player
     to act on" from a client-supplied UserId/name argument can be tricked into acting on a
     different player's data.
   - Remotes with no visible type/shape validation and no rate limiting are exploitable by any
     client that can fire an event as fast as the network allows.

2. SERVER AUTHORITY
   - Currency, inventory, health, combat resolution, rewards, and purchases must be computed
     and written on the server. Roblox exploits can already alter any client-side Lua state and
     any RemoteEvent payload, so a client that can set its own leaderstats/currency value
     locally, or a server that trusts a client-reported outcome, has no real protection.

3. ROJO PROJECT STRUCTURE
   - A default.project.json (or other Rojo project file) tree node under ReplicatedStorage,
     ReplicatedFirst, StarterPlayer, StarterGui, StarterPack, or Workspace is downloaded to and
     readable by every client. Server-only source mapped into one of those containers ships
     server implementation — and any logic or secrets in it — to every exploiter.

4. DATASTORE SAFETY
   - GetAsync/SetAsync/UpdateAsync/IncrementAsync/RemoveAsync can throw (throttling, outages)
     and must be wrapped in pcall/xpcall, or an unhandled error silently loses a save.
   - A read-then-write on the same key should use UpdateAsync, not GetAsync followed by
     SetAsync — two concurrent servers (multi-server games, rejoin) racing a
     GetAsync+SetAsync pair can overwrite each other's write.
   - Without BindToClose, a server shutdown can skip the final save for players still in session.
   - A DataStore call inside a loop over many players/keys should check
     DataStoreService:GetRequestBudgetForRequestType(...) or stagger with task.wait() —
     the request budget is shared per experience across every server, so one server bursting
     past it (e.g. saving all players at once) throttles saves everywhere.

5. RECEIPT PROCESSING
   - MarketplaceService.ProcessReceipt must always return an Enum.ProductPurchaseDecision;
     returning nothing/a bare boolean causes Roblox to keep retrying or never confirm the
     receipt.
   - The grant must be idempotent against receiptInfo.PurchaseId — a retried receipt (the
     documented retry-on-NotProcessedYet behavior) must not grant the reward twice.
   - The grant itself should be pcall-wrapped; an unhandled error mid-grant risks a paid
     purchase never reaching the player. A silently missing grant or a silent double-grant are
     both zero-tolerance bugs in a shipped game.
   - Developer Products must be granted from ProcessReceipt only. PromptProductPurchaseFinished
     only reflects when the purchase dialog closed, not a confirmed backend transaction —
     granting there can pay out a purchase that later fails, or miss one that settles after the
     prompt closes. Game Passes are different: PromptGamePassPurchaseFinished + a rejoin-time
     UserOwnsGamePassAsync check is the correct, Roblox-documented pattern for those.

6. CONNECTIONS AND PERFORMANCE
   - A signal :Connect( made inside PlayerAdded, a loop, or any code path that can re-run
     (respawn, retry) leaks another live connection unless it is stored and :Disconnect()'d.
   - wait()/spawn()/delay() are deprecated legacy globals; task.wait()/task.spawn()/task.delay()
     are more precise and lighter-weight.
   - game:GetService( and FindFirstChild( with a literal name inside a per-frame
     Heartbeat/RenderStepped/Stepped connection re-resolve every frame instead of caching once
     outside the loop.
   - `while true do` with no wait/task.wait/signal:Wait() inside will not yield and can hang the
     thread (and, on the server, the game's Heartbeat).

7. TEXT FILTERING
   - Any player-authored text shown to other players (chat, signs, name tags, custom UI) must go
     through TextService:FilterStringAsync(...) (or TextChatService) before being broadcast. A
     remote handler that re-broadcasts a textual argument via FireAllClients/FireClient with no
     filtering call violates Roblox's content policy and can get an experience moderated.

8. ADMIN BACKDOORS
   - Privileged/admin checks must compare player.UserId, never player.Name or
     player.DisplayName — DisplayName is entirely player-chosen, and usernames can be changed and
     later recycled by a different account. A real incident: a player renamed themselves to
     match a game owner's name-based admin check and gained full owner powers.

When reviewing, cite the exact line/pattern that's missing or risky and give the exact fix.
Static analysis here cannot see cross-file dispatch (e.g. a generic remote that routes to a
validated handler elsewhere) or confirm real client/server placement beyond the Rojo project
file, so treat findings as leads to verify against the actual script context, not proof.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "scan_repository_statically",
                "description": "Run every deterministic Luau/Rojo check across an entire repository: call arity, use-before-definition, deprecated schedulers, unprotected yielding calls, Player.Chatted under TextChatService, unanchored parts, shadow-casting lights in loops, discarded per-frame connections, Rojo path and service-placement errors, unset Lighting.Technology, and authored content fields nothing reads. Needs no model call and works on any repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "root": {"type": "string", "description": "Path to the repository root to scan"},
                        "rules": {"type": "array", "items": {"type": "string"}, "description": "Optional subset of rule names to run"},
                    },
                    "required": ["root"],
                },
            },
            {
                "name": "audit_remote_validation",
                "description": "Review a RemoteEvent/RemoteFunction server handler for missing input validation, missing rate limiting, and player-identity trust-boundary violations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source containing the OnServerEvent/OnServerInvoke handler"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_server_authority",
                "description": "Review code for client-side writes to authoritative state (currency, inventory, health) that should be server-owned.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source to review"},
                        "is_client_script": {"type": "boolean", "description": "Whether this script runs client-side (LocalScript / StarterPlayerScripts / StarterGui)"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_rojo_project_structure",
                "description": "Check a Rojo project.json tree for server-only source mapped into a client-visible service (ReplicatedStorage, StarterPlayer, StarterGui, StarterPack, Workspace, ReplicatedFirst).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_json": {"type": "string", "description": "The contents of the Rojo *.project.json file"},
                    },
                    "required": ["project_json"],
                },
            },
            {
                "name": "audit_datastore_usage",
                "description": "Audit DataStore calls for missing pcall wrapping, SetAsync used for a read-modify-write instead of UpdateAsync, and a missing BindToClose save.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source containing DataStore calls"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_connection_leaks",
                "description": "Detect signal :Connect( calls made inside PlayerAdded/loops/re-entrant code paths without a matching :Disconnect(.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source to review"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_performance_patterns",
                "description": "Flag deprecated wait()/spawn()/delay(), uncached game:GetService( inside per-frame connections, and unyielding while-true loops.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source to review"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_receipt_processing",
                "description": "Review a MarketplaceService.ProcessReceipt callback for a missing PurchaseDecision return, missing idempotency, and unprotected grant logic; also flags granting a Developer Product from PromptProductPurchaseFinished instead of ProcessReceipt.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source containing the ProcessReceipt/PromptProductPurchaseFinished callback"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_text_filtering",
                "description": "Detect a remote handler that re-broadcasts a textual payload (FireAllClients/FireClient) with no visible TextService/TextChatService filtering call.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source containing the remote handler"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_admin_backdoor",
                "description": "Detect privileged/admin access gated by comparing player.Name or player.DisplayName to a hardcoded string instead of the spoof-proof player.UserId.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source to review"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_validation_script",
                "description": "Review a Roblox project's Node validation/build script for unsafe dynamic command execution.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Node validation or build script source"},
                        "script_name": {"type": "string", "description": "The relative script path"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_luau_module",
                "description": "Review every Roblox Luau module for high-signal unsafe dynamic or outbound execution patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source"},
                        "module_name": {"type": "string", "description": "The relative module path"},
                    },
                    "required": ["code"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "scan_repository_statically": self._scan_repository_statically,
            "audit_remote_validation": self._audit_remote_validation,
            "audit_server_authority": self._audit_server_authority,
            "review_rojo_project_structure": self._review_rojo_project_structure,
            "audit_datastore_usage": self._audit_datastore_usage,
            "audit_connection_leaks": self._audit_connection_leaks,
            "audit_performance_patterns": self._audit_performance_patterns,
            "review_receipt_processing": self._review_receipt_processing,
            "audit_text_filtering": self._audit_text_filtering,
            "audit_admin_backdoor": self._audit_admin_backdoor,
            "review_validation_script": self._review_validation_script,
            "review_luau_module": self._review_luau_module,
        }

    def _scan_repository_statically(self, root: str, rules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Deterministic whole-repository scan.

        Every other tool here asks a model for judgement. This one does not
        need one: the checks it runs are arithmetic and pattern facts, so it
        is exact, free, and fast enough to run on every commit.
        """
        return analyze_repository(root, rules)

    def _review_validation_script(self, code: str, script_name: str = "") -> Dict[str, Any]:
        """Review Node validation/build scripts for unsafe command construction."""
        findings = []
        if re.search(r"\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{", code):
            findings.append({
                "severity": "HIGH",
                "issue": "Validation/build script interpolates values into a shell command.",
                "fix": "Use execFile/execFileSync with an argument array and validate every value before spawning a command.",
            })
        if re.search(r"\b(?:exec|execSync)\s*\(\s*[^,\n]+\+", code):
            findings.append({
                "severity": "MEDIUM",
                "issue": "Validation/build script concatenates a shell command string.",
                "fix": "Prefer execFile/execFileSync with explicit argv to avoid shell interpretation.",
            })
        return {"findings": findings, "script": script_name}

    def _review_luau_module(self, code: str, module_name: str = "") -> Dict[str, Any]:
        """Review a Luau module for high-signal unsafe execution patterns."""
        findings = []
        if re.search(r"\b(?:loadstring|LoadString)\s*\(", code):
            findings.append({
                "severity": "CRITICAL",
                "issue": "Luau dynamically executes source with loadstring.",
                "fix": "Remove dynamic code execution and route behavior through fixed server-owned modules.",
            })
        if re.search(r"\bHttpGet\s*\(", code) and "HttpService" in code:
            findings.append({
                "severity": "HIGH",
                "issue": "Luau performs an outbound HTTP request from a source module.",
                "fix": "Keep external requests behind a server-only, allowlisted adapter with timeout, validation, and failure handling.",
            })
        return {"findings": findings, "module": module_name}

    # ── Remote trust boundary ────────────────────────────────────────

    def _audit_remote_validation(self, code: str) -> Dict[str, Any]:
        findings = []

        stripped = _strip_luau_noise(code)
        handlers = list(_iter_remote_handlers(stripped))

        if not handlers:
            return {"findings": [], "total_issues": 0, "note": "No OnServerEvent/OnServerInvoke handler found in this snippet"}

        # Scoped per handler: a file can define more than one remote, and a
        # validated handler must not suppress a missing-validation finding on
        # a sibling handler in the same file that never checks its arguments.
        for trusted_param, body in handlers:
            if not re.search(r"\btypeof\s*\(|\btype\s*\(|\bassert\s*\(|\bmath\.clamp\s*\(", body):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "No visible type/shape validation (typeof/type/assert/math.clamp) on incoming remote arguments",
                    "fix": "Validate every non-player argument's type and range before acting on it — e.g. assert(typeof(amount) == \"number\" and amount >= 0 and amount <= MAX_AMOUNT)",
                })

            if not re.search(r"(?i)debounce|cooldown|rate[_-]?limit|last[A-Z]\w*Time|os\.clock\s*\(\s*\)\s*-", body):
                findings.append({
                    "severity": "LOW",
                    "issue": "No visible per-player rate limiting/debounce on this remote handler",
                    "fix": "Track a last-fired timestamp per player (e.g. via os.clock()) and reject calls inside a minimum interval, or route through a shared rate-limit module",
                })

            lookup_match = re.search(r"GetPlayerByUserId\s*\(\s*(\w+)", body)
            if lookup_match and lookup_match.group(1) != trusted_param:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"Handler resolves a player via GetPlayerByUserId({lookup_match.group(1)}) from client-supplied data instead of relying on the trusted `{trusted_param}` argument the engine already provides",
                    "fix": f"Act on `{trusted_param}` directly (the real sender) instead of a client-supplied UserId/name, or explicitly verify the resolved player equals `{trusted_param}` before proceeding",
                })

        return {"findings": findings, "total_issues": len(findings)}

    # ── Server authority ─────────────────────────────────────────────

    def _audit_server_authority(self, code: str, is_client_script: bool = False) -> Dict[str, Any]:
        findings = []

        code = _strip_luau_noise(code)
        looks_client_side = is_client_script or bool(re.search(r"\bLocalPlayer\b", code))
        if not looks_client_side:
            return {"findings": [], "total_issues": 0, "note": "No client-side evidence (LocalPlayer) found in this snippet"}

        if re.search(r"leaderstats\b[^\n]*\.Value\s*[:+\-*/]?=(?!=)", code):
            findings.append({
                "severity": "HIGH",
                "issue": "A leaderstats value is written directly from client-side code — an exploit can set this to any value since the server does not own this write",
                "fix": "Move this write to a server script/service and have the client only request the change via a validated RemoteEvent",
            })

        if any(method in code for method in _DATASTORE_METHODS):
            findings.append({
                "severity": "CRITICAL",
                "issue": "DataStoreService is referenced from client-reachable code — DataStore APIs only work on the server, and finding this here means server persistence logic (or a copy of it) is living in shared/client-replicated source",
                "fix": "Move DataStore access into a server-only script/service (ServerScriptService/ServerStorage) and expose only a validated remote for the client to trigger a save/load",
            })

        return {"findings": findings, "total_issues": len(findings)}

    # ── Rojo project structure ────────────────────────────────────────

    def _review_rojo_project_structure(self, project_json: str) -> Dict[str, Any]:
        try:
            project = json.loads(project_json)
        except (json.JSONDecodeError, TypeError) as exc:
            return {"findings": [], "total_issues": 0, "error": f"Could not parse project JSON: {exc}"}

        tree = project.get("tree") if isinstance(project, dict) else None
        if not isinstance(tree, dict):
            return {"findings": [], "total_issues": 0, "note": "No 'tree' object found in this project file"}

        findings: List[Dict[str, Any]] = []

        def walk(node: Any, service: Optional[str], location: str) -> None:
            if not isinstance(node, dict):
                return
            path = node.get("$path")
            if isinstance(path, str) and service in _CLIENT_VISIBLE_SERVICES:
                normalized = path.replace("\\", "/").lower()
                segments = normalized.split("/")
                if any(hint in segments for hint in _SERVER_SOURCE_HINTS) or any(
                    seg.startswith("server") for seg in segments
                ):
                    findings.append({
                        "severity": "CRITICAL",
                        "issue": f"'{location}' maps '{path}' into {service}, a client-visible service — this ships that source to every client, where it can be read and decompiled by exploiters",
                        "fix": f"Move this source under ServerScriptService or ServerStorage instead of {service}, or split out only the client-safe portion to keep here",
                    })
            for key, value in node.items():
                if key.startswith("$"):
                    continue
                next_service = service if service is not None else (key if key[:1].isupper() else None)
                walk(value, next_service, f"{location}.{key}" if location else key)

        walk(tree, None, "")

        return {"findings": findings, "total_issues": len(findings)}

    # ── DataStore safety ──────────────────────────────────────────────

    def _audit_datastore_usage(self, code: str) -> Dict[str, Any]:
        findings = []

        code = _strip_luau_noise(code)
        if not any(method in code for method in _DATASTORE_METHODS):
            return {"findings": [], "total_issues": 0, "note": "No DataStore method calls found in this snippet"}

        protected_spans = [
            (m.end(), _matching_paren_end(code, m.end()))
            for m in re.finditer(r"\b(?:pcall|xpcall)\s*\(", code)
        ]

        unwrapped_calls = []
        for method in _DATASTORE_METHODS:
            for match in re.finditer(rf"[:.]" + method + r"\s*\(", code):
                if not any(start <= match.start() < end for start, end in protected_spans):
                    unwrapped_calls.append(method)

        if unwrapped_calls:
            findings.append({
                "severity": "HIGH",
                "issue": f"DataStore call(s) not wrapped in an enclosing pcall/xpcall: {', '.join(sorted(set(unwrapped_calls)))}",
                "fix": "Wrap every DataStore call in pcall(function() ... end) (or xpcall with a handler) and check the returned ok flag before trusting the result",
            })

        if re.search(r"GetAsync\s*\(", code) and re.search(r"SetAsync\s*\(", code):
            findings.append({
                "severity": "MEDIUM",
                "issue": "GetAsync followed by SetAsync on what looks like a read-modify-write — two concurrent servers/sessions can race and one write can silently overwrite the other",
                "fix": "Use UpdateAsync(key, function(oldValue) ... return newValue end) for read-modify-write instead of a separate GetAsync + SetAsync pair",
            })

        if not re.search(r"BindToClose\s*\(", code):
            findings.append({
                "severity": "LOW",
                "issue": "No BindToClose handler found alongside DataStore usage",
                "fix": "Add game:BindToClose(function() ... end) to give in-session players a final save attempt before the server shuts down",
            })

        # A DataStore call inside a loop with no budget check or stagger can
        # burst well past DataStoreService:GetRequestBudgetForRequestType()'s
        # per-experience limit when the player count is high, throttling
        # everyone's saves — not just the loop's own.
        for loop_match in re.finditer(r"\b(?:for|while)\b[^\n]*?\bdo\b", code):
            body_end = _block_end(code, loop_match.end())
            loop_body = code[loop_match.end() : body_end]
            if any(re.search(rf"[:.]{method}\s*\(", loop_body) for method in _DATASTORE_METHODS):
                if not re.search(r"GetRequestBudgetForRequestType|task\.wait\s*\(|\bwait\s*\(", loop_body):
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "A DataStore call runs inside a loop with no request-budget check (GetRequestBudgetForRequestType) or stagger (task.wait) between iterations — looping over many players/keys can burst past the shared per-experience request budget and throttle everyone's saves",
                        "fix": "Check DataStoreService:GetRequestBudgetForRequestType(...) before each call in the loop, and/or add a small task.wait() between iterations so a large player count doesn't burst past the budget",
                    })
                    break

        return {"findings": findings, "total_issues": len(findings)}

    # ── Connection leaks ──────────────────────────────────────────────

    def _audit_connection_leaks(self, code: str) -> Dict[str, Any]:
        findings = []

        if not re.search(r":\s*Connect\s*\(", code):
            return {"findings": [], "total_issues": 0, "note": "No :Connect( calls found in this snippet"}

        stripped = _strip_luau_noise(code)
        disconnect_count = len(re.findall(r":\s*Disconnect\s*\(", stripped))

        # A per-player signal (player.CharacterAdded, humanoid.Died, ...) is
        # owned by an instance Roblox destroys when the player leaves, and
        # Instance:Destroy() disconnects its own connections — so nesting
        # those alone isn't a leak. A RunService per-frame signal is global
        # and outlives the player entirely; nesting *that* inside a
        # PlayerAdded/CharacterAdded handler with no :Disconnect( anywhere in
        # the file leaks one more live frame listener per join/respawn,
        # forever, each still closing over a player who may be long gone.
        if disconnect_count == 0:
            for entry_match in re.finditer(
                r"(?:PlayerAdded|CharacterAdded)\s*:\s*Connect\s*\(\s*function\s*\([^)]*\)", stripped
            ):
                body_end = _block_end(stripped, entry_match.end())
                body = stripped[entry_match.end() : body_end]
                if _FRAME_SIGNAL_RE.search(body):
                    findings.append({
                        "severity": "HIGH",
                        "issue": "A RunService per-frame signal (Heartbeat/Stepped/RenderStepped) is connected inside a PlayerAdded/CharacterAdded handler with no :Disconnect( anywhere in the file — each (re)join/respawn leaks another live frame listener that keeps running and referencing a player who may already be gone",
                        "fix": "Store the returned RBXScriptConnection and disconnect it in the matching PlayerRemoving/CharacterRemoving handler, or use a per-player Maid/Trove that cleans up on removal",
                    })
                    break

        for loop_match in re.finditer(r"\b(?:for|while)\b[^\n]*?\bdo\b", stripped):
            body_end = _block_end(stripped, loop_match.end())
            loop_body = stripped[loop_match.end() : body_end]
            if re.search(r":\s*Connect\s*\(", loop_body) and ":Disconnect(" not in loop_body:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "A signal connection is created inside a loop body with no visible :Disconnect( in that same loop — if this loop can run more than once (not just a one-time startup pass), each run adds another live connection",
                    "fix": "Move the :Connect( call outside the loop if it only needs to run once, or disconnect the previous connection before creating a new one each iteration",
                })
                break

        return {"findings": findings, "total_issues": len(findings)}

    # ── Performance ────────────────────────────────────────────────────

    def _audit_performance_patterns(self, code: str) -> Dict[str, Any]:
        findings = []

        # A leading '.'/':' means this is a method/field call (e.g. a custom
        # EnemyService:spawn() or someone's own .delay() helper), not the
        # deprecated bare global — only a call with no receiver is the
        # legacy wait()/spawn()/delay() this check is meant to catch.
        if re.search(r"(?<![:.\w])\bwait\s*\(", code):
            findings.append({
                "severity": "INFO",
                "issue": "wait() is deprecated — it has extra scheduling overhead and lower precision than task.wait()",
                "fix": "Replace wait(...) with task.wait(...)",
            })

        if re.search(r"(?<![:.\w])\b(spawn|delay)\s*\(", code):
            findings.append({
                "severity": "INFO",
                "issue": "spawn()/delay() are deprecated legacy globals",
                "fix": "Replace with task.spawn(...) / task.delay(...)",
            })

        stripped = _strip_luau_noise(code)

        for frame_match in re.finditer(
            r"(?:Heartbeat|RenderStepped|Stepped)\s*:\s*Connect\s*\(\s*function\s*\([^)]*\)", stripped
        ):
            body_end = _block_end(stripped, frame_match.end())
            body = stripped[frame_match.end() : body_end]
            if re.search(r"game\s*:\s*GetService\s*\(", body):
                findings.append({
                    "severity": "LOW",
                    "issue": "game:GetService( is called inside a per-frame Heartbeat/RenderStepped/Stepped connection — it re-resolves the service every frame",
                    "fix": "Cache the service reference in a local/module-level variable outside the per-frame connection",
                })
                break

        for frame_match in re.finditer(
            r"(?:Heartbeat|RenderStepped|Stepped)\s*:\s*Connect\s*\(\s*function\s*\([^)]*\)", stripped
        ):
            body_end = _block_end(stripped, frame_match.end())
            body = stripped[frame_match.end() : body_end]
            if re.search(r":\s*FindFirstChild\s*\(\s*[\"']", body):
                findings.append({
                    "severity": "LOW",
                    "issue": "FindFirstChild( with a literal name is called inside a per-frame Heartbeat/RenderStepped/Stepped connection — it walks the hierarchy every frame instead of once",
                    "fix": "Look the instance up once outside the per-frame connection and cache the reference (re-resolving only on AncestryChanged/CharacterAdded if it can be replaced)",
                })
                break

        for loop_match in re.finditer(r"\bwhile\s+true\s+do\b", stripped):
            body_end = _block_end(stripped, loop_match.end())
            body = stripped[loop_match.end() : body_end]
            # RBXScriptSignal:Wait() (RunService.Heartbeat:Wait(), a
            # RemoteEvent's OnServerEvent:Wait(), etc.) yields the thread
            # just as effectively as wait()/task.wait() — recognize any
            # `:Wait(` call, not only the named globals.
            if not re.search(r"\bwait\s*\(|\btask\.wait\s*\(|\byield\s*\(|:\s*Wait\s*\(", body):
                findings.append({
                    "severity": "HIGH",
                    "issue": "`while true do` loop has no visible wait/task.wait/signal:Wait() inside it — an unyielding loop will not release the thread and can hang the script (and, on the server, the game's Heartbeat)",
                    "fix": "Add a task.wait(...) inside the loop body, or restructure as a Heartbeat/RunService connection instead of a manual loop",
                })
                break

        return {"findings": findings, "total_issues": len(findings)}

    # ── Receipt processing ────────────────────────────────────────────

    def _review_receipt_processing(self, code: str) -> Dict[str, Any]:
        stripped = _strip_luau_noise(code)
        has_process_receipt = "ProcessReceipt" in stripped
        prompt_match = re.search(r"Prompt(?:Product)?PurchaseFinished\s*:\s*Connect\s*\(\s*function\s*\([^)]*\)", stripped)

        if not has_process_receipt and not prompt_match:
            return {"findings": [], "total_issues": 0, "note": "No ProcessReceipt/PromptProductPurchaseFinished callback found in this snippet"}

        findings = []

        if has_process_receipt:
            assign_match = re.search(r"ProcessReceipt\s*=\s*function\s*\([^)]*\)", stripped)
            body = stripped[assign_match.end() : _block_end(stripped, assign_match.end())] if assign_match else stripped

            if not re.search(r"Enum\.ProductPurchaseDecision", body):
                findings.append({
                    "severity": "HIGH",
                    "issue": "ProcessReceipt callback never returns Enum.ProductPurchaseDecision — Roblox requires an explicit decision or it will keep retrying and the receipt is never confirmed",
                    "fix": "Return Enum.ProductPurchaseDecision.PurchaseGranted after a successful grant, or Enum.ProductPurchaseDecision.NotProcessedYet if the grant could not be completed (e.g. DataStore unavailable)",
                })

            if not re.search(r"PurchaseId", body):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "No visible check against receiptInfo.PurchaseId — a retried receipt (Roblox retries on NotProcessedYet) can grant the reward twice with no idempotency guard",
                    "fix": "Record granted PurchaseIds per player and check for a duplicate before granting again",
                })

            if not re.search(r"\b(pcall|xpcall)\s*\(", body):
                findings.append({
                    "severity": "HIGH",
                    "issue": "The purchase grant is not wrapped in pcall/xpcall — an unhandled error mid-grant risks a paid purchase never reaching the player",
                    "fix": "Wrap the DataStore/grant logic in pcall(function() ... end) and only return PurchaseGranted if it succeeded",
                })

        if prompt_match:
            prompt_body = stripped[prompt_match.end() : _block_end(stripped, prompt_match.end())]
            if re.search(r"[:.](?:Set|Update|Increment)Async\s*\(|leaderstats\b[^\n]*\.Value\s*[:+\-*/]?=(?!=)", prompt_body):
                findings.append({
                    "severity": "HIGH",
                    "issue": "PromptProductPurchaseFinished appears to grant the reward directly — this event only reflects when the purchase dialog closed, not a confirmed backend transaction, so it can grant a purchase that later fails, or miss one that settles after the prompt closes",
                    "fix": "Grant Developer Product rewards only from MarketplaceService.ProcessReceipt, which Roblox retries until you return Enum.ProductPurchaseDecision.PurchaseGranted; use PromptProductPurchaseFinished only for UI feedback (Game Pass grants via PromptGamePassPurchaseFinished + UserOwnsGamePassAsync are a separate, correct pattern)",
                })

        return {"findings": findings, "total_issues": len(findings)}

    # ── Text filtering ─────────────────────────────────────────────────

    def _audit_text_filtering(self, code: str) -> Dict[str, Any]:
        stripped = _strip_luau_noise(code)
        handlers = list(_iter_remote_handlers(stripped))

        if not handlers:
            return {"findings": [], "total_issues": 0, "note": "No OnServerEvent/OnServerInvoke handler found in this snippet"}

        findings = []
        for _trusted_param, body in handlers:
            if _TEXT_FILTER_INDICATOR_RE.search(body):
                continue
            for fire_match in _BROADCAST_CALL_RE.finditer(body):
                call_end = _matching_paren_end(body, fire_match.end())
                args = body[fire_match.end() : call_end - 1]
                if _TEXTUAL_ARG_NAME_RE.search(args):
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "This remote handler broadcasts a textual-looking argument to other clients (FireAllClients/FireClient) with no visible TextService/TextChatService filtering call — unfiltered player-authored text reaching other players violates Roblox's community standards and content policy",
                        "fix": "Run player-authored text through TextService:FilterStringAsync(text, fromUserId):GetNonChatStringForBroadcastAsync() (or route it through TextChatService) before broadcasting it to other clients",
                    })
                    break

        return {"findings": findings, "total_issues": len(findings)}

    # ── Admin backdoor ─────────────────────────────────────────────────

    def _audit_admin_backdoor(self, code: str) -> Dict[str, Any]:
        stripped = _strip_luau_noise(code)
        matches = list(_IDENTITY_STRING_COMPARE_RE.finditer(stripped))

        if not matches:
            return {"findings": [], "total_issues": 0, "note": "No player.Name/DisplayName string comparison found in this snippet"}

        findings = []
        for match in matches:
            window_start = max(0, match.start() - 250)
            window_end = min(len(stripped), match.end() + 250)
            if not _ADMIN_KEYWORDS_RE.search(stripped[window_start:window_end]):
                continue
            prop = match.group(1)
            spoof_reason = (
                "DisplayName is entirely player-chosen and can be set to anything"
                if prop == "DisplayName"
                else "usernames can be changed and later recycled by a different account"
            )
            findings.append({
                "severity": "CRITICAL" if prop == "DisplayName" else "HIGH",
                "issue": f"Privileged access appears to be gated by comparing player.{prop} to a hardcoded string — {spoof_reason}, so this check can be defeated by any player who sets their {'display name' if prop == 'DisplayName' else 'username'} to the expected value",
                "fix": "Compare player.UserId to a hardcoded numeric ID (or table of IDs) instead — UserId is assigned once per account and cannot be changed by the player",
            })

        return {"findings": findings, "total_issues": len(findings)}
