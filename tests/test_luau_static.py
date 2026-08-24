"""Every rule in luau_static must fire on a real defect and stay silent on
correct code.

Both halves matter equally. A rule that never fires is dead weight that reads
like coverage, and a rule that fires on correct code gets the whole scanner
muted -- which is worse than not having written it, because the muting takes
the working rules down with it.

The call-arity case is the exact shape of the outage this module was built
for: a builder gained a required parameter and one call site kept the old
argument list.
"""

import os
import tempfile

from agents.luau_static import analyze_repository


def scan(files: dict, rules=None):
    with tempfile.TemporaryDirectory() as root:
        for relative, body in files.items():
            path = os.path.join(root, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
        return analyze_repository(root, rules)


def rules_fired(report):
    return {finding["rule"] for finding in report["findings"]}


# ── Correctness ──────────────────────────────────────────────────────


def test_call_arity_catches_the_outage_shape():
    report = scan({"src/World.luau": """--!strict
local function buildSocket(parent: Instance, center: Vector3, extra: { any })
    table.insert(extra, parent)
    return center
end

local function build()
    buildSocket(workspace, Vector3.zero)
end
"""})
    findings = [f for f in report["findings"] if f["rule"] == "call_arity"]
    assert len(findings) == 1
    assert "buildSocket" in findings[0]["issue"]
    assert findings[0]["severity"] == "HIGH"


def test_call_arity_accepts_optional_parameters():
    report = scan({"src/World.luau": """--!strict
local function place(target: Instance, scale: number, yaw: number?)
    return target, scale, yaw
end

local function run()
    place(workspace, 1)
end
"""})
    assert "call_arity" not in rules_fired(report)


def test_call_arity_ignores_methods_taking_self():
    report = scan({"src/Service.luau": """--!strict
local function helper(self: any, value: number)
    return value
end
local Service = {}
function Service.go(instance)
    return instance:helper(1)
end
return Service
"""})
    assert "call_arity" not in rules_fired(report)


def test_call_arity_stays_quiet_when_a_name_is_shadowed():
    """An inner helper must not manufacture failures against the outer one."""
    report = scan({"src/World.luau": """--!strict
local function tree(parent: Instance, position: Vector3, scale: number)
    return parent, position, scale
end

local function backdrop()
    local function inner(a: number, b: number, c: number, d: number, e: number)
        return a + b + c + d + e
    end
    inner(1, 2, 3, 4, 5)
    tree(workspace, Vector3.zero, 1)
end
"""})
    assert "call_arity" not in rules_fired(report)


def test_use_before_definition():
    report = scan({"src/Init.luau": """--!strict
local result = helper(1)

local function helper(value: number)
    return value
end
return result
"""})
    assert "use_before_definition" in rules_fired(report)


# ── Roblox runtime ───────────────────────────────────────────────────


def test_player_chatted_is_flagged():
    report = scan({"src/Admin.luau": """--!strict
local Players = game:GetService("Players")
Players.PlayerAdded:Connect(function(player)
    player.Chatted:Connect(function(message: string)
        print(message)
    end)
end)
"""})
    assert "player_chatted" in rules_fired(report)


def test_findfirstchild_nil_use():
    report = scan({"src/Rig.luau": """--!strict
local function go(character: Model)
    return character:FindFirstChild("Humanoid").Health
end
return go
"""})
    assert "findfirstchild_nil" in rules_fired(report)


def test_findfirstchild_guarded_is_silent():
    report = scan({"src/Rig.luau": """--!strict
local function go(character: Model)
    local humanoid = character:FindFirstChild("Humanoid")
    if humanoid == nil then
        return 0
    end
    return (humanoid :: Humanoid).Health
end
return go
"""})
    assert "findfirstchild_nil" not in rules_fired(report)


def test_deprecated_scheduler_and_api():
    report = scan({"src/Legacy.luau": """
local part = Instance.new("Part", workspace)
part.Anchored = true
wait(1)
part:Remove()
"""})
    fired = rules_fired(report)
    assert "deprecated_scheduler" in fired
    assert "deprecated_api" in fired


def test_unanchored_part_only_when_file_never_anchors():
    noisy = scan(
        {"src/Build.luau": 'local p = Instance.new("Part")\np.Parent = workspace\n'}
    )
    assert "unanchored_part" in rules_fired(noisy)

    quiet = scan(
        {"src/Build.luau": 'local p = Instance.new("Part")\np.Anchored = true\n'}
    )
    assert "unanchored_part" not in rules_fired(quiet)


def test_connection_leak_only_when_handle_is_discarded():
    discarded = scan({"src/Loop.luau": """
local RunService = game:GetService("RunService")
RunService.Heartbeat:Connect(function() end)
"""})
    assert "connection_leak" in rules_fired(discarded)

    kept = scan({"src/Loop.luau": """
local RunService = game:GetService("RunService")
local connection = RunService.Heartbeat:Connect(function() end)
return connection
"""})
    assert "connection_leak" not in rules_fired(kept)


def test_per_frame_allocation():
    report = scan({"src/Frame.luau": """
local RunService = game:GetService("RunService")
RunService.RenderStepped:Connect(function()
    for _, child in workspace:GetChildren() do
        print(child)
    end
end)
"""})
    assert "per_frame_allocation" in rules_fired(report)


def test_shadow_light_in_loop():
    report = scan({"src/Lights.luau": """
for index = 1, 40 do
    local light = Instance.new("PointLight")
    light.Shadows = true
    light.Parent = workspace
end
"""})
    assert "shadow_light_in_loop" in rules_fired(report)


def test_unprotected_async():
    report = scan({"src/Save.luau": """
local DataStoreService = game:GetService("DataStoreService")
local store = DataStoreService:GetDataStore("Main")
local function save(key: string, value: any)
    store:SetAsync(key, value)
end
return save
"""})
    assert "unprotected_async" in rules_fired(report)


def test_unprotected_async_silent_when_wrapped():
    report = scan({"src/Save.luau": """
local DataStoreService = game:GetService("DataStoreService")
local store = DataStoreService:GetDataStore("Main")
local function save(key: string, value: any)
    local ok = pcall(function()
        store:SetAsync(key, value)
    end)
    return ok
end
return save
"""})
    assert "unprotected_async" not in rules_fired(report)


def test_gameplay_clock():
    report = scan({"src/Cooldown.luau": """
local function ready(last: number)
    local cooldown = 5
    return os.time() - last > cooldown
end
return ready
"""})
    assert "gameplay_clock" in rules_fired(report)


def test_unresolved_require():
    report = scan(
        {
            "src/Main.luau": "local Gone = require(script.Parent.DeletedModule)\nreturn Gone\n",
            "src/Present.luau": "return {}\n",
        }
    )
    assert "unresolved_require" in rules_fired(report)

    ok = scan(
        {
            "src/Main.luau": "local Present = require(script.Parent.Present)\nreturn Present\n",
            "src/Present.luau": "return {}\n",
        }
    )
    assert "unresolved_require" not in rules_fired(ok)


# ── Rojo ─────────────────────────────────────────────────────────────


def test_rojo_missing_path_and_unset_lighting():
    report = scan(
        {
            "default.project.json": """{
  "name": "Demo",
  "tree": {
    "$className": "DataModel",
    "ServerScriptService": { "$path": "src/does_not_exist" }
  }
}""",
            "src/Present.luau": "return {}\n",
        }
    )
    fired = rules_fired(report)
    assert "rojo_missing_path" in fired
    assert "rojo_lighting_unset" in fired


def test_rojo_lighting_declared_is_silent():
    report = scan(
        {
            "default.project.json": """{
  "name": "Demo",
  "tree": {
    "$className": "DataModel",
    "Lighting": { "$properties": { "Technology": "Future" } }
  }
}""",
            "src/Present.luau": "return {}\n",
        }
    )
    assert "rojo_lighting_unset" not in rules_fired(report)


def test_rojo_server_source_in_client_service():
    report = scan(
        {
            "default.project.json": """{
  "name": "Demo",
  "tree": {
    "$className": "DataModel",
    "Lighting": { "$properties": { "Technology": "Future" } },
    "ReplicatedStorage": { "Shared": { "$path": "src/server" } }
  }
}""",
            "src/server/Secret.luau": "return {}\n",
        }
    )
    assert "rojo_server_in_client" in rules_fired(report)


def test_test_project_is_not_asked_for_lighting():
    report = scan(
        {
            "test.project.json": """{
  "name": "Tests",
  "tree": { "$className": "DataModel" }
}""",
            "src/Present.luau": "return {}\n",
        }
    )
    assert "rojo_lighting_unset" not in rules_fired(report)


# ── Content wiring ───────────────────────────────────────────────────


def test_unread_definition_field():
    report = scan(
        {
            "src/shared/Content/Definitions/Events.luau": """--!strict
return {
    {
        id = "a",
        guidanceLine = "turn the latch",
    },
    {
        id = "b",
        guidanceLine = "split up",
    },
    {
        id = "c",
        guidanceLine = "hold the line",
    },
}
""",
            "src/server/Service.luau": "--!strict\nlocal x = 1\nreturn x\n",
        }
    )
    fired = [f for f in report["findings"] if f["rule"] == "unread_definition_field"]
    assert any("guidanceLine" in f["issue"] for f in fired)


def test_read_definition_field_is_silent():
    report = scan(
        {
            "src/shared/Content/Definitions/Events.luau": """--!strict
return {
    {
        id = "a",
        guidanceLine = "turn the latch",
    },
    {
        id = "b",
        guidanceLine = "split up",
    },
    {
        id = "c",
        guidanceLine = "hold the line",
    },
}
""",
            "src/server/Service.luau": "--!strict\nreturn function(d) return d.guidanceLine end\n",
        }
    )
    fired = [f for f in report["findings"] if f["rule"] == "unread_definition_field"]
    assert not any("guidanceLine" in f["issue"] for f in fired)


# ── Report shape ─────────────────────────────────────────────────────


def test_clean_repository_reports_nothing():
    report = scan(
        {
            "default.project.json": """{
  "name": "Demo",
  "tree": {
    "$className": "DataModel",
    "Lighting": { "$properties": { "Technology": "Future" } },
    "ServerScriptService": { "$path": "src" }
  }
}""",
            "src/Clean.luau": """--!strict
local function add(left: number, right: number): number
    return left + right
end
return add(1, 2)
""",
        }
    )
    assert report["total_issues"] == 0, report["findings"]


def test_report_is_sorted_and_tallied():
    report = scan({"src/Mixed.luau": """
local Players = game:GetService("Players")
Players.PlayerAdded:Connect(function(player)
    player.Chatted:Connect(function() end)
end)
wait(1)
"""})
    severities = [f["severity"] for f in report["findings"]]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    assert severities == sorted(severities, key=lambda s: order[s])
    assert sum(report["by_rule"].values()) == report["total_issues"]


# ── Precision regressions ────────────────────────────────────────────
#
# Every case below is a shape this scanner reported as a defect on a working
# production codebase. Of thirteen findings on its first real run, twelve were
# these. They are kept as tests because precision is the thing that decides
# whether anyone leaves the scanner switched on.


def test_method_named_spawn_is_not_the_deprecated_global():
    report = scan({"src/Night.luau": """--!strict
local function beat(enemyService: any, id: string)
    enemyService:spawn(id)
end
return beat
"""})
    assert "deprecated_scheduler" not in rules_fired(report)


def test_throttled_frame_callback_is_not_per_frame_allocation():
    report = scan({"src/Step.luau": """
local RunService = game:GetService("RunService")
local Players = game:GetService("Players")
local accumulator = 0
RunService.Heartbeat:Connect(function(deltaTime)
    accumulator += deltaTime
    if accumulator < 0.5 then
        return
    end
    accumulator = 0
    for _, player in Players:GetPlayers() do
        print(player)
    end
end)
"""})
    assert "per_frame_allocation" not in rules_fired(report)


def test_type_schema_is_not_authored_content():
    """A type export beside content looks exactly like content to a regex."""
    report = scan(
        {
            "src/shared/Content/Registry.luau": """--!strict
export type Entry = {
    displayNameKey: string,
    analyticsKey: string,
    assetBundle: string,
}
local ALLOWED = {
    displayNameKey = true,
    analyticsKey = true,
    assetBundle = true,
}
return ALLOWED
""",
            "src/server/Use.luau": "--!strict\nreturn 1\n",
        }
    )
    assert "unread_definition_field" not in rules_fired(report)


def test_startup_connection_is_not_a_leak():
    report = scan({"src/Service.luau": """
local RunService = game:GetService("RunService")
local Service = {}
function Service.Start(self)
    RunService.Heartbeat:Connect(function() end)
end
return Service
"""})
    assert "connection_leak" not in rules_fired(report)


def test_chatted_alongside_textchatcommand_is_deliberate():
    report = scan({"src/Admin.luau": """--!strict
local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local command = Instance.new("TextChatCommand")
command.PrimaryAlias = "/go"
command.Parent = TextChatService
Players.PlayerAdded:Connect(function(player)
    player.Chatted:Connect(function() end)
end)
"""})
    assert "player_chatted" not in rules_fired(report)
