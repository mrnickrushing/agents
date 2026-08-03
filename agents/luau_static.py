"""Deterministic whole-repo static analysis for Roblox/Luau projects.

Every other check in this package hands source to a model and asks what it
thinks. That is the right shape for judgement calls -- is this remote
validated, is this receipt flow correct -- and the wrong shape for the class
of bug this module exists for.

It exists because of a specific outage. In a shipped game, a builder function
gained a required parameter and one of its call sites was not updated. Luau
passed `nil`, `table.insert` threw, the service that owned the world failed to
initialize, and an entire region of the game stopped existing. It shipped that
way through nine published versions. Nothing caught it: the test suite only
asserted that modules were *present* in the built place, and the type checker
ran on a platform that could not see the file at all.

A model was never going to catch that reliably either -- it is not a
judgement call, it is arithmetic on argument counts. So everything here is
deterministic, needs no API key, and runs over a whole repository in a second.

Precision is the design constraint, not coverage. A checker that cries wolf
gets muted, and a muted checker is worth less than no checker, so every rule
here is written to stay quiet unless it is confident. Where a rule cannot be
sure -- a name defined twice with no scope tracking, a property set through a
variable it cannot follow -- it declines to report rather than guess.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

OPENERS = "([{"
CLOSERS = ")]}"

SKIP_DIRECTORIES = {
    ".git", "node_modules", "build", "dist", "out", "__pycache__",
    ".rokit", "Packages", "ServerPackages", "DevPackages", ".vscode",
}

# Calls that reach the network, the datastore, or the asset pipeline. Each can
# fail for reasons the caller does not control, and an unprotected failure
# takes down whatever thread it runs on.
YIELDING_CALLS = (
    "GetAsync", "SetAsync", "UpdateAsync", "IncrementAsync", "RemoveAsync",
    "GetSortedAsync", "GetOrderedDataStore", "LoadCharacter",
    "LoadAsset", "GetProductInfo", "UserOwnsGamePassAsync",
    "GetUserThumbnailAsync", "RequestStreamAroundAsync", "PromptPurchase",
    "PublishAsync", "GetPlayerPlaceInstanceAsync", "TeleportAsync",
    "ReserveServer", "HttpGet", "RequestAsync", "GetHumanoidDescriptionFromUserId",
)

CREATABLE_PARTS = ("Part", "MeshPart", "WedgePart", "TrussPart", "CornerWedgePart", "SpawnLocation")


def strip_noise(code: str) -> str:
    """Blank comments and string bodies, preserving line and column counts.

    Positions are reported back to a human, so every replacement keeps the
    same width and the same number of newlines as what it replaced.
    """

    def blank(match: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"--\[(=*)\[.*?\]\1\]", blank, code, flags=re.DOTALL)
    text = re.sub(r"--[^\n]*", blank, text)
    text = re.sub(r"\[(=*)\[.*?\]\1\]", blank, text, flags=re.DOTALL)
    text = re.sub(
        r"([\"'])(?:\\.|(?!\1).)*?\1",
        lambda m: m.group(1) + " " * (len(m.group(0)) - 2) + m.group(1),
        text,
    )
    return text


def strip_comments(code: str) -> str:
    """Blank comments but keep string literals intact.

    `strip_noise` empties string bodies, which is right for structural
    matching and fatal for any rule that needs to know *which* string --
    `Instance.new("Part")` is invisible to it. Two rules learned this the
    hard way and could never fire.
    """

    def blank(match: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"--\[(=*)\[.*?\]\1\]", blank, code, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", blank, text)


def close_paren(text: str, start: int) -> int:
    """Index of the bracket matching the one at `start`, or -1 if unbalanced."""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
            if depth == 0:
                return index
    return -1


def split_top_level(inner: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    current = ""
    for char in inner:
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    if current.strip():
        parts.append(current)
    return [p.strip() for p in parts if p.strip()]


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def iter_luau_files(root: str) -> Iterable[str]:
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [d for d in subdirectories if d not in SKIP_DIRECTORIES]
        for filename in filenames:
            if filename.endswith((".luau", ".lua")):
                yield os.path.join(directory, filename)


class Finding(dict):
    def __init__(self, rule: str, severity: str, path: str, line: int, issue: str, fix: str):
        super().__init__(
            rule=rule, severity=severity, file=path, line=line, issue=issue, fix=fix
        )


# ── Correctness ──────────────────────────────────────────────────────


def check_call_arity(path: str, source: str) -> List[Finding]:
    """Calls passing fewer arguments than the function requires.

    This is the rule the module was built for. A parameter typed `T?` is
    optional. Methods taking `self` are skipped because they are invoked with
    `:` and the counts do not line up. When a name is defined more than once
    in a file the smallest requirement wins: there is no scope tracking here,
    and an inner helper shadowing an outer one must not manufacture failures
    against the outer one's call sites.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    signatures: Dict[str, Tuple[int, int]] = {}

    for match in re.finditer(r"local function ([A-Za-z_]\w*)\(", text):
        opened = match.end() - 1
        closed = close_paren(text, opened)
        if closed < 0:
            continue
        params = split_top_level(text[opened + 1 : closed])
        if params and params[0].split(":")[0].strip() == "self":
            continue
        required = sum(1 for p in params if not re.search(r":\s*.*\?\s*$", p))
        name = match.group(1)
        known = signatures.get(name)
        if known is None or required < known[1]:
            signatures[name] = (len(params), required)

    for name, (total, required) in signatures.items():
        if required == 0:
            continue
        for call in re.finditer(r"(?<![\w.:])" + re.escape(name) + r"\(", text):
            opened = call.end() - 1
            closed = close_paren(text, opened)
            if closed < 0:
                continue
            inner = text[opened + 1 : closed]
            passed = len(split_top_level(inner)) if inner.strip() else 0
            if passed < required:
                findings.append(Finding(
                    "call_arity", "HIGH", path, line_of(text, call.start()),
                    f"{name}() is called with {passed} argument(s) but requires {required} of {total}",
                    f"Pass the missing argument(s). Luau supplies nil silently, so this surfaces "
                    f"as a nil-index or nil-argument error deep inside {name}, far from this line.",
                ))
    return findings


def check_use_before_definition(path: str, source: str) -> List[Finding]:
    """A local function called above the line that defines it.

    `local function f` is not hoisted. Calling it earlier in the same chunk
    reads the local as nil, and the failure reads as "attempt to call a nil
    value" pointing at a name that is plainly defined in the file.

    Only top-level definitions are considered, and only calls that are
    themselves at top level, because a call inside another function body may
    legitimately run after both are defined.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    definitions = {
        m.group(1): m.start()
        for m in re.finditer(r"^local function ([A-Za-z_]\w*)\(", text, re.M)
    }
    for name, defined_at in definitions.items():
        for call in re.finditer(r"^\s{0,3}(?:local \w+ = )?" + re.escape(name) + r"\(", text, re.M):
            if call.start() < defined_at:
                findings.append(Finding(
                    "use_before_definition", "HIGH", path, line_of(text, call.start()),
                    f"{name}() is called before `local function {name}` on line {line_of(text, defined_at)}",
                    "local functions are not hoisted; the name is nil until its definition runs. "
                    "Move the definition above this call, or forward-declare with `local name`.",
                ))
    return findings


# ── Roblox runtime hazards ───────────────────────────────────────────


def check_deprecated_scheduler(path: str, source: str) -> List[Finding]:
    text = strip_noise(source)
    findings: List[Finding] = []
    # A method named spawn/wait/delay is not the deprecated global. Excluding
    # only `.` missed `self._enemyService:spawn(...)`.
    for match in re.finditer(r"(?<![\w.:])(wait|spawn|delay)\s*\(", text):
        name = match.group(1)
        findings.append(Finding(
            "deprecated_scheduler", "LOW", path, line_of(text, match.start()),
            f"`{name}()` is the deprecated global scheduler",
            f"Use task.{name}() — the globals throttle unpredictably under load and "
            f"`spawn`/`delay` can defer far longer than asked.",
        ))
    return findings


def check_unprotected_async(path: str, source: str) -> List[Finding]:
    """Yielding, failure-prone calls made outside pcall.

    Only flags a call with no `pcall` anywhere in the enclosing 12 lines,
    which is deliberately loose: the point is to find calls written as though
    they cannot fail, not to police exactly where the pcall sits.
    """
    text = strip_noise(source)
    lines = text.split("\n")
    findings: List[Finding] = []
    for index, line in enumerate(lines):
        for call in YIELDING_CALLS:
            if not re.search(r"[.:]" + re.escape(call) + r"\s*\(", line):
                continue
            if re.search(r"GetService\s*\(", line):
                continue
            if True:
                window = "\n".join(lines[max(0, index - 6) : index + 6])
                if "pcall" in window or "xpcall" in window:
                    continue
                findings.append(Finding(
                    "unprotected_async", "MEDIUM", path, index + 1,
                    f"{call} is called without a nearby pcall",
                    "Wrap it in pcall and handle the failure. Datastore, asset and teleport "
                    "calls fail for reasons the caller does not control, and an unhandled "
                    "error kills the thread that was mid-way through something.",
                ))
                break
    return findings


def check_player_chatted(path: str, source: str) -> List[Finding]:
    text = strip_noise(source)
    # Keeping Chatted next to a registered TextChatCommand is the correct
    # belt-and-braces: only one of the two can fire in a given experience.
    if "TextChatCommand" in source:
        return []
    findings: List[Finding] = []
    for match in re.finditer(r"\.Chatted\s*:\s*Connect", text):
        findings.append(Finding(
            "player_chatted", "HIGH", path, line_of(text, match.start()),
            "Player.Chatted does not fire when the experience uses TextChatService",
            "TextChatService is the default for new experiences, and Player.Chatted is a "
            "legacy-chat event. Register a TextChatCommand (set AutocompleteVisible = false "
            "to keep it out of the autocomplete list) or handle TextChannel messages instead.",
        ))
    return findings


def check_unanchored_parts(path: str, source: str) -> List[Finding]:
    """Parts created in code without Anchored ever being set.

    Scoped to the file: if the file never mentions `.Anchored` at all, every
    part it creates falls. If it sets Anchored anywhere, this stays quiet
    rather than trying to match each creation to its assignment.
    """
    text = strip_comments(source)
    if "Anchored" in text:
        return []
    findings: List[Finding] = []
    for match in re.finditer(r'Instance\.new\(\s*"(' + "|".join(CREATABLE_PARTS) + r')"', text):
        findings.append(Finding(
            "unanchored_part", "MEDIUM", path, line_of(text, match.start()),
            f'Instance.new("{match.group(1)}") in a file that never sets Anchored',
            "Parts are unanchored by default and will fall out of the world. Set "
            "`part.Anchored = true` for scenery, or make the physics intent explicit.",
        ))
    return findings


def check_shadow_lights_in_loops(path: str, source: str) -> List[Finding]:
    """Shadow-casting lights created inside a loop.

    Under Future lighting every shadow-casting light is paid for each frame.
    A light created in a loop is a light created many times, and the count is
    rarely what the author had in mind when they turned shadows on.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    for match in re.finditer(r"Shadows\s*=\s*true", text):
        before = text[max(0, match.start() - 900) : match.start()]
        if re.search(r"\n\s*(for|while)\b[^\n]*\bdo\b", before):
            findings.append(Finding(
                "shadow_light_in_loop", "MEDIUM", path, line_of(text, match.start()),
                "A shadow-casting light is created inside a loop",
                "Under Future lighting each one costs every frame. Cast shadows only from "
                "lights a player looks for a shadow from, and leave decorative fill lights "
                "with Shadows = false.",
            ))
    return findings


def check_connection_leaks(path: str, source: str) -> List[Finding]:
    """Per-frame connections whose handle is thrown away.

    A connection stored on `self` or in a local is one somebody can still
    disconnect, so only a discarded return value counts. The first version of
    this rule flagged fourteen correct call sites in a real codebase, every
    one of which had kept its handle.
    """
    text = strip_noise(source)
    if re.search(r":\s*Disconnect\s*\(|\bConnectionsTo\w*\b|:\s*Once\s*\(", text):
        return []
    findings: List[Finding] = []
    for match in re.finditer(r"(RenderStepped|Heartbeat|Stepped)\s*:\s*Connect\s*\(", text):
        # A connection opened during service startup lives as long as the
        # server does. There is nothing to leak into, because the thing it
        # serves never goes away.
        preceding = text[max(0, match.start() - 2000) : match.start()]
        if re.search(r"function \w+[.:](Start|Init)\s*\(", preceding):
            continue
        # A connection assigned to something is a connection someone kept a
        # handle on, which is the whole prerequisite for disconnecting it
        # later. Only a discarded return value is unambiguously unrecoverable.
        line_start = text.rfind("\n", 0, match.start()) + 1
        if re.search(r"=\s*$", text[line_start : match.start()].rstrip() + " ".rstrip()) or "=" in text[line_start : match.start()]:
            continue
        findings.append(Finding(
            "connection_leak", "MEDIUM", path, line_of(text, match.start()),
            f"{match.group(1)} is connected in a file that never calls Disconnect",
            "A per-frame connection that outlives what it was watching keeps running and "
            "keeps its upvalues alive. Store the connection and disconnect it when the "
            "thing it serves goes away.",
        ))
    return findings


# ── Rojo / place configuration ───────────────────────────────────────


CLIENT_VISIBLE = {
    "ReplicatedStorage", "ReplicatedFirst", "StarterPlayer", "StarterGui",
    "StarterPack", "Workspace", "Lighting",
}


def check_rojo_project(path: str, raw: str, repo_root: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        project = json.loads(raw)
    except json.JSONDecodeError as error:
        return [Finding("rojo_unparsable", "HIGH", path, 1,
                        f"Rojo project is not valid JSON: {error}",
                        "Fix the syntax; Rojo cannot build this project at all.")]

    tree = project.get("tree")
    if not isinstance(tree, dict):
        return findings

    def walk(node: Any, service: Optional[str], location: str) -> None:
        if not isinstance(node, dict):
            return
        source = node.get("$path")
        if isinstance(source, str):
            resolved = os.path.join(repo_root, source)
            if not os.path.exists(resolved):
                findings.append(Finding(
                    "rojo_missing_path", "HIGH", path, 1,
                    f'{location} maps $path "{source}", which does not exist',
                    "Rojo silently produces an empty container for a missing path, so the "
                    "code simply is not in the built place. Fix the path or remove the entry.",
                ))
            if service in CLIENT_VISIBLE and re.search(r"(^|/)(server|Server)(/|$)", source):
                findings.append(Finding(
                    "rojo_server_in_client", "HIGH", path, 1,
                    f'{location} maps server source "{source}" into client-visible {service}',
                    "Anything under a client-visible service is readable by every player. "
                    "Move it to ServerScriptService or ServerStorage.",
                ))
        for key, value in node.items():
            if key.startswith("$"):
                continue
            walk(value, service if service else key, f"{location}.{key}")

    for key, value in tree.items():
        if key.startswith("$"):
            continue
        walk(value, key, key)

    # Only the shipping project. A test or dev project deliberately configures
    # nothing, and telling someone their test harness has no lighting is noise.
    basename = os.path.basename(path).lower()
    if any(marker in basename for marker in ("test", "dev", "spec")):
        return findings

    lighting = tree.get("Lighting")
    technology = None
    if isinstance(lighting, dict):
        technology = (lighting.get("$properties") or {}).get("Technology")
    if technology is None:
        findings.append(Finding(
            "rojo_lighting_unset", "MEDIUM", path, 1,
            "The project never configures Lighting.Technology",
            "Technology cannot be set from a script — it exists only in the place file, so "
            "leaving it out means shipping whatever the place already had. Declare it "
            "explicitly (Future for per-light shadows) so the lighting you author is the "
            "lighting that ships.",
        ))
    return findings


# ── Content wiring ───────────────────────────────────────────────────


def check_unread_definition_fields(repo_root: str, sources: Dict[str, str]) -> List[Finding]:
    """Fields authored in content definitions that nothing ever reads.

    Found a real one: every encounter in a shipped game authored a line of
    guidance telling a stuck player what to do, worded differently for solo
    and group play, and no code path read either. The content was written,
    reviewed, and invisible.

    Only files under a Content/Definitions path are treated as authored data,
    and a field must appear at least three times there before absence
    elsewhere is called a problem -- a field used once is more likely a
    one-off than a systematically dropped one.
    """
    # A type export or a validation allow-list lives beside the content it
    # describes and looks exactly like it to a regex. Reading a schema as
    # authored data reported five fields as unused that were never data at
    # all -- they were the shape the data has to take.
    definition_files = {}
    for path, text in sources.items():
        if not re.search(r"(Content|Definitions|Catalog|Config)[/\\]", path):
            continue
        if re.search(r"^export type |^type \w+ = {", text, re.M):
            continue
        definition_files[path] = text
    if not definition_files:
        return []

    authored: Dict[str, int] = {}
    for text in definition_files.values():
        for match in re.finditer(r"^\s{4,}([a-z][A-Za-z]*)\s*=", strip_noise(text), re.M):
            authored[match.group(1)] = authored.get(match.group(1), 0) + 1

    consumers = "\n".join(
        strip_noise(text) for path, text in sources.items() if path not in definition_files
    )
    findings: List[Finding] = []
    for field, count in sorted(authored.items()):
        if count < 3 or len(field) < 5:
            continue
        if re.search(r"[.\[][\"']?" + re.escape(field) + r"\b", consumers):
            continue
        findings.append(Finding(
            "unread_definition_field", "MEDIUM", next(iter(definition_files)), 1,
            f'Authored field "{field}" appears {count} times in content definitions '
            f"but is never read outside them",
            "Either surface it or delete it. Authored content that nothing consumes is "
            "indistinguishable at runtime from content that was never written, which is "
            "how it survives review.",
        ))
    return findings


# ── Module wiring ────────────────────────────────────────────────────


def check_strict_mode(path: str, source: str) -> List[Finding]:
    """A Luau module without --!strict gets almost no type checking.

    Only flags modules that already carry type annotations: a file written
    with types but left in nonstrict mode is asking for checking it does not
    receive, whereas an untyped file is a deliberate choice.
    """
    head = source[:400]
    if re.search(r"^--!\s*(strict|nonstrict|nocheck)", head, re.M):
        return []
    if not re.search(r"\)\s*:\s*[A-Z]\w+|:\s*(string|number|boolean)\b", source):
        return []
    return [Finding(
        "missing_strict_mode", "LOW", path, 1,
        "Module carries type annotations but no --!strict header",
        "Add `--!strict` as the first line. Without it Luau checks almost nothing, "
        "so the annotations describe intent without enforcing it.",
    )]


def check_deprecated_api(path: str, source: str) -> List[Finding]:
    text = strip_noise(source)
    findings: List[Finding] = []
    for match in re.finditer(r"[.:]Remove\s*\(\s*\)", text):
        findings.append(Finding(
            "deprecated_api", "MEDIUM", path, line_of(text, match.start()),
            ":Remove() is deprecated and only reparents the instance",
            "Use :Destroy(). Remove() sets Parent to nil but leaves the instance alive with "
            "its connections intact, which is a memory leak that looks like deletion.",
        ))
    for match in re.finditer(r'Instance\.new\(\s*"[A-Za-z]+"\s*,', strip_comments(source)):
        findings.append(Finding(
            "deprecated_api", "LOW", path, line_of(text, match.start()),
            "Instance.new() is passing a parent as its second argument",
            "Set .Parent last, after the properties. Parenting first makes the instance "
            "replicate and re-render on every subsequent property write.",
        ))
    return findings


def check_unresolved_requires(path: str, source: str, known: set) -> List[Finding]:
    """A require naming a module that does not exist anywhere in the repo.

    Only path-style requires with a trailing identifier are considered, and a
    name that matches any module file in the tree passes. That is loose on
    purpose -- resolving Roblox instance paths exactly needs the Rojo tree --
    but it still catches the case that matters: a module renamed or deleted
    while a require kept pointing at the old name.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    for match in re.finditer(r"require\s*\(([^)]*)\)", text):
        target = match.group(1).strip()
        tail = re.findall(r"[.\/]([A-Za-z_]\w*)\s*$", target)
        if not tail:
            continue
        name = tail[0]
        if name in known or name in {"Parent", "script", "game"}:
            continue
        findings.append(Finding(
            "unresolved_require", "HIGH", path, line_of(text, match.start()),
            f'require targets "{name}", which matches no module file in the repository',
            "A require that resolves to nothing throws at load and takes the whole script "
            "with it. Fix the path, or restore the module it was renamed from.",
        ))
    return findings


def check_findfirstchild_nil(path: str, source: str) -> List[Finding]:
    """FindFirstChild indexed immediately, with no nil check.

    FindFirstChild returns nil by design; WaitForChild is the one that
    guarantees an instance. Indexing the result on the same expression is the
    single most common runtime error in Roblox code.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    for match in re.finditer(r"FindFirstChild\s*\([^)]*\)\s*[.:]\s*[A-Za-z_]", text):
        findings.append(Finding(
            "findfirstchild_nil", "HIGH", path, line_of(text, match.start()),
            "The result of FindFirstChild is indexed without a nil check",
            "FindFirstChild returns nil when the child is absent, so this throws the moment "
            "it is. Assign it, test for nil, then use it -- or use WaitForChild if the child "
            "is guaranteed to arrive.",
        ))
    return findings


def check_per_frame_allocation(path: str, source: str) -> List[Finding]:
    """GetChildren/GetDescendants inside a per-frame callback.

    Both allocate a fresh table every call. At sixty frames a second on a
    model of any size that is the dominant cost in the callback.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    for connect in re.finditer(r"(RenderStepped|Heartbeat|Stepped)\s*:\s*Connect\s*\(", text):
        body = text[connect.end() : connect.end() + 1400]
        # An accumulator that returns early is the standard way to run
        # something a few times a second inside a per-frame signal. The
        # allocation is real but it is not happening every frame, and saying
        # so anyway trains people to ignore the rule.
        if re.search(r"(?s)accumulator|elapsed|sinceLast|\bif\s+\w+\s*<\s*[\d.]+\s*then\s*return", body[:400]):
            continue
        for call in re.finditer(r":(GetChildren|GetDescendants|GetPlayers)\s*\(", body):
            findings.append(Finding(
                "per_frame_allocation", "MEDIUM", path,
                line_of(text, connect.end() + call.start()),
                f":{call.group(1)}() is called inside a {connect.group(1)} callback",
                "It allocates a new table every frame. Cache the list and refresh it when the "
                "thing it describes actually changes.",
            ))
            break
    return findings


def check_gameplay_clock(path: str, source: str) -> List[Finding]:
    """os.time()/tick() used for gameplay timing.

    Neither agrees between server and client. Anything a player is timed
    against has to come from a clock both sides read the same way.
    """
    text = strip_noise(source)
    findings: List[Finding] = []
    for match in re.finditer(r"\b(os\.time|tick)\s*\(\s*\)", text):
        window = text[max(0, match.start() - 200) : match.start() + 200]
        if not re.search(r"(?i)cooldown|expire|remaining|deadline|elapsed|duration|timer", window):
            continue
        findings.append(Finding(
            "gameplay_clock", "MEDIUM", path, line_of(text, match.start()),
            f"{match.group(1)}() is used for gameplay timing",
            "os.time() is whole seconds and tick() is machine-local; neither agrees across "
            "the server/client boundary. Use workspace:GetServerTimeNow() for anything a "
            "player is timed against.",
        ))
    return findings


def check_hardcoded_asset_ids(path: str, source: str) -> List[Finding]:
    """rbxassetid literals scattered through logic rather than declared once."""
    text = strip_noise(source)
    ids = list(re.finditer(r"rbxassetid://(\d+)", source))
    if len(ids) < 4:
        return []
    if re.search(r"(?i)registry|catalog|manifest|assets?\s*=|_IDS\b", path + text[:600]):
        return []
    return [Finding(
        "scattered_asset_ids", "LOW", path, line_of(source, ids[0].start()),
        f"{len(ids)} rbxassetid literals are declared inline in this module",
        "Collect them into one registry table. Inline IDs cannot be audited, swapped for a "
        "fallback, or checked against an upload manifest.",
    )]


# ── Entry point ──────────────────────────────────────────────────────

FILE_RULES = (
    check_call_arity,
    check_strict_mode,
    check_deprecated_api,
    check_findfirstchild_nil,
    check_per_frame_allocation,
    check_gameplay_clock,
    check_hardcoded_asset_ids,
    check_use_before_definition,
    check_deprecated_scheduler,
    check_unprotected_async,
    check_player_chatted,
    check_unanchored_parts,
    check_shadow_lights_in_loops,
    check_connection_leaks,
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def analyze_repository(root: str, rules: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run every deterministic check across a repository.

    `root` is any directory; nothing here is specific to one project. Returns
    findings sorted most severe first, with a per-rule tally so a caller can
    see at a glance which class of problem dominates.
    """
    root = os.path.abspath(root)
    sources: Dict[str, str] = {}
    for absolute in iter_luau_files(root):
        try:
            sources[os.path.relpath(absolute, root)] = open(
                absolute, encoding="utf-8", errors="replace"
            ).read()
        except OSError:
            continue

    module_names = {
        os.path.splitext(os.path.basename(p))[0] for p in sources
    }

    findings: List[Finding] = []
    for relative, text in sources.items():
        if not rules or "unresolved_requires" in rules:
            findings.extend(check_unresolved_requires(relative, text, module_names))
        for rule in FILE_RULES:
            if rules and rule.__name__.replace("check_", "") not in rules:
                continue
            findings.extend(rule(relative, text))

    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [d for d in subdirectories if d not in SKIP_DIRECTORIES]
        for filename in filenames:
            if filename.endswith(".project.json"):
                absolute = os.path.join(directory, filename)
                relative = os.path.relpath(absolute, root)
                if rules and "rojo_project" not in rules:
                    continue
                try:
                    raw = open(absolute, encoding="utf-8").read()
                except OSError:
                    continue
                findings.extend(check_rojo_project(relative, raw, root))

    if not rules or "unread_definition_fields" in rules:
        findings.extend(check_unread_definition_fields(root, sources))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 3), f["file"], f["line"]))

    tally: Dict[str, int] = {}
    for finding in findings:
        tally[finding["rule"]] = tally.get(finding["rule"], 0) + 1

    return {
        "root": root,
        "files_scanned": len(sources),
        "findings": findings,
        "total_issues": len(findings),
        "by_rule": tally,
        "by_severity": {
            level: sum(1 for f in findings if f["severity"] == level)
            for level in ("HIGH", "MEDIUM", "LOW")
        },
    }
