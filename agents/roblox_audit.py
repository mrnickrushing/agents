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
    doesn't trip over "end"/"do" appearing inside a comment or string."""
    text = re.sub(r"--\[(=*)\[.*?\]\1\]", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.DOTALL)
    text = re.sub(r"--[^\n]*", "", text)
    text = re.sub(r"\[(=*)\[.*?\]\1\]", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    text = re.sub(r"([\"'])(?:\\.|(?!\1).)*\1", "", text)
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


class RobloxAuditAgent(BaseAgent):
    """
    Roblox/Luau specialist: remote validation, server authority, DataStore
    safety, Rojo project structure, connection leaks, receipt processing.
    """

    name = "roblox_audit"
    description = (
        "Reviews Roblox/Luau code for remote-event trust boundaries, server authority, "
        "DataStore safety, Rojo project structure, connection leaks, and MarketplaceService "
        "receipt processing."
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

5. RECEIPT PROCESSING
   - MarketplaceService.ProcessReceipt must always return an Enum.ProductPurchaseDecision;
     returning nothing/a bare boolean causes Roblox to keep retrying or never confirm the
     receipt.
   - The grant must be idempotent against receiptInfo.PurchaseId — a retried receipt (the
     documented retry-on-NotProcessedYet behavior) must not grant the reward twice.
   - The grant itself should be pcall-wrapped; an unhandled error mid-grant risks a paid
     purchase never reaching the player. A silently missing grant or a silent double-grant are
     both zero-tolerance bugs in a shipped game.

6. CONNECTIONS AND PERFORMANCE
   - A signal :Connect( made inside PlayerAdded, a loop, or any code path that can re-run
     (respawn, retry) leaks another live connection unless it is stored and :Disconnect()'d.
   - wait()/spawn()/delay() are deprecated legacy globals; task.wait()/task.spawn()/task.delay()
     are more precise and lighter-weight.
   - game:GetService( inside a per-frame Heartbeat/RenderStepped/Stepped connection re-resolves
     the service every frame instead of caching it once outside the loop.
   - `while true do` with no wait/task.wait inside will not yield and can hang the thread (and,
     on the server, the game's Heartbeat).

When reviewing, cite the exact line/pattern that's missing or risky and give the exact fix.
Static analysis here cannot see cross-file dispatch (e.g. a generic remote that routes to a
validated handler elsewhere) or confirm real client/server placement beyond the Rojo project
file, so treat findings as leads to verify against the actual script context, not proof.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
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
                "description": "Review a MarketplaceService.ProcessReceipt callback for a missing PurchaseDecision return, missing idempotency, and unprotected grant logic.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Luau source containing the ProcessReceipt callback"},
                    },
                    "required": ["code"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "audit_remote_validation": self._audit_remote_validation,
            "audit_server_authority": self._audit_server_authority,
            "review_rojo_project_structure": self._review_rojo_project_structure,
            "audit_datastore_usage": self._audit_datastore_usage,
            "audit_connection_leaks": self._audit_connection_leaks,
            "audit_performance_patterns": self._audit_performance_patterns,
            "review_receipt_processing": self._review_receipt_processing,
        }

    # ── Remote trust boundary ────────────────────────────────────────

    def _audit_remote_validation(self, code: str) -> Dict[str, Any]:
        findings = []

        stripped = _strip_luau_noise(code)
        handler_matches = list(
            re.finditer(r"OnServerEvent\s*:\s*Connect\s*\(\s*function\s*\(\s*(\w+)", stripped)
        ) + list(re.finditer(r"OnServerInvoke\s*=\s*function\s*\(\s*(\w+)", stripped))

        if not handler_matches:
            return {"findings": [], "total_issues": 0, "note": "No OnServerEvent/OnServerInvoke handler found in this snippet"}

        # Scoped per handler: a file can define more than one remote, and a
        # validated handler must not suppress a missing-validation finding on
        # a sibling handler in the same file that never checks its arguments.
        for match in handler_matches:
            trusted_param = match.group(1)
            body_end = _block_end(stripped, match.end())
            body = stripped[match.end() : body_end]

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
        if "ProcessReceipt" not in stripped:
            return {"findings": [], "total_issues": 0, "note": "No ProcessReceipt callback found in this snippet"}

        findings = []

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

        return {"findings": findings, "total_issues": len(findings)}
