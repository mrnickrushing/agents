"""Precision regressions from the first real dashboard scan of a Roblox
game (Roblox-Game, 9 findings — every one a false positive)."""

from agents.roblox_audit import RobloxAuditAgent


def _issues(result):
    return [f["issue"] for f in result["findings"]]


def test_player_only_handlers_need_no_argument_validation():
    agent = RobloxAuditAgent()
    code = """
resetCourseEvent.OnServerEvent:Connect(function(player)
    if not allowReset(player) then
        return
    end
    resetRun(player)
end)
"""
    issues = _issues(agent._audit_remote_validation(code))
    assert not any("type/shape validation" in i for i in issues)


def test_project_throttle_helpers_count_as_rate_limiting():
    agent = RobloxAuditAgent()
    code = """
local allowSprintApply = RemoteThrottle.create(0.1)
sprintStateEvent.OnServerEvent:Connect(function(player, wantsToSprint)
    if type(wantsToSprint) ~= "boolean" then
        return
    end
    if allowSprintApply(player) then
        applyMovement(player)
    end
end)
"""
    issues = _issues(agent._audit_remote_validation(code))
    assert not any("rate limiting" in i for i in issues)

    bare = """
dropEvent.OnServerEvent:Connect(function(player, amount)
    if type(amount) ~= "number" then return end
    give(player, amount)
end)
"""
    assert any(
        "rate limiting" in i for i in _issues(agent._audit_remote_validation(bare))
    )


def test_receipt_ledger_in_a_helper_counts_as_idempotency():
    agent = RobloxAuditAgent()
    code = """
local function grantSkip(player, receiptInfo)
    progressStore:UpdateAsync("player_" .. player.UserId, function(oldData)
        return PurchaseLedger.applyStageSkip(oldData, receiptInfo.PurchaseId, os.time())
    end)
    return true
end

MarketplaceService.ProcessReceipt = function(receiptInfo)
    local player = Players:GetPlayerByUserId(receiptInfo.PlayerId)
    if not player then
        return Enum.ProductPurchaseDecision.NotProcessedYet
    end
    local ok, granted = pcall(grantSkip, player, receiptInfo)
    return ok and granted and Enum.ProductPurchaseDecision.PurchaseGranted
        or Enum.ProductPurchaseDecision.NotProcessedYet
end
"""
    issues = _issues(agent._review_receipt_processing(code))
    assert not any("PurchaseId" in i for i in issues)

    naive = """
MarketplaceService.ProcessReceipt = function(receiptInfo)
    local player = Players:GetPlayerByUserId(receiptInfo.PlayerId)
    giveCoins(player, 100)
    return Enum.ProductPurchaseDecision.PurchaseGranted
end
"""
    assert any(
        "PurchaseId" in i for i in _issues(agent._review_receipt_processing(naive))
    )


def test_connections_on_instances_created_in_the_loop_are_not_leaks():
    agent = RobloxAuditAgent()
    code = """
local function addRunes(positions)
    for index, position in ipairs(positions) do
        local rune = platform("Rune" .. index, position)
        rune.Touched:Connect(function(hit)
            activate(index, hit)
        end)
    end
end
"""
    assert not any(
        "inside a loop" in i for i in _issues(agent._audit_connection_leaks(code))
    )

    leak = """
local function refresh()
    for _, part in ipairs(parts) do
        part.Touched:Connect(onTouch)
    end
end
"""
    assert any(
        "inside a loop" in i for i in _issues(agent._audit_connection_leaks(leak))
    )


def test_throttled_heartbeat_lookups_are_not_per_frame():
    agent = RobloxAuditAgent()
    code = """
local accumulator = 0
RunService.Heartbeat:Connect(function(deltaTime)
    accumulator += deltaTime
    if accumulator < 0.2 then
        return
    end
    accumulator = 0
    for player in pairs(playerState) do
        local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
    end
end)
"""
    assert not any(
        "FindFirstChild" in i for i in _issues(agent._audit_performance_patterns(code))
    )

    hot = """
RunService.Heartbeat:Connect(function()
    local root = workspace:FindFirstChild("Lobby")
end)
"""
    assert any(
        "FindFirstChild" in i for i in _issues(agent._audit_performance_patterns(hot))
    )


# --- Delegated validation (lastlight, 2026-08) ------------------------------


def test_validation_delegated_to_a_named_helper_counts_as_validation():
    agent = RobloxAuditAgent()
    code = """
local function isValidAmount(amount)
    return typeof(amount) == "number" and amount >= 0
end
buyEvent.OnServerEvent:Connect(function(player, amount)
    if not isValidAmount(amount) then
        return
    end
    local last = lastAt[player]
    if last and os.clock() - last < 1 then
        return
    end
    lastAt[player] = os.clock()
    grant(player, amount)
end)
"""
    assert not any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code))
    )


def test_a_helper_that_does_not_actually_validate_is_still_reported():
    agent = RobloxAuditAgent()
    code = """
local function giveMoney(player, amount)
    player.leaderstats.Coins.Value += amount
end
buyEvent.OnServerEvent:Connect(function(player, amount)
    giveMoney(player, amount)
end)
"""
    assert any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code))
    )


def test_validation_in_a_required_module_is_only_visible_once_inlined():
    """The validator lives one `require` away. Judged on the handler's file
    alone the remote looks unvalidated; given the module it requires, it is
    plainly validated — which is the whole point of resolving Luau requires."""
    agent = RobloxAuditAgent()
    code = """
local Contract = require(script.Parent.Contract)
actionEvent.OnServerEvent:Connect(function(player, payload)
    if not Contract.isValidTransport(payload) then
        return
    end
    local last = lastAt[player]
    if last and os.clock() - last < 1 then
        return
    end
    lastAt[player] = os.clock()
    apply(player, payload)
end)
"""
    imported = """
local Contract = {}
function Contract.isValidTransport(payload)
    if type(payload) ~= "table" then
        return false
    end
    return true
end
return Contract
"""
    assert any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code))
    )
    assert not any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code, imported))
    )


def test_transport_shim_relaying_to_an_injected_callback_is_not_reported():
    """A NetworkService that owns the RemoteEvents and forwards each payload
    to whichever handler the composition root registered has neither the
    validation nor the throttle to do — and the registered handler lives in a
    file it never imports, so no require resolution can reach it."""
    agent = RobloxAuditAgent()
    code = """
performanceReport.OnServerEvent:Connect(function(player: Player, payload: any)
    local handler = self._performanceHandler
    if handler ~= nil then
        handler(player, payload)
    end
end)
"""
    assert _issues(agent._audit_remote_validation(code)) == []


def test_client_data_passed_into_an_engine_call_is_not_a_transport_shim():
    """`store:SetAsync(key, data)` passes the payload straight through too,
    but method-syntax calls act on it rather than relay it onward."""
    agent = RobloxAuditAgent()
    code = """
saveEvent.OnServerEvent:Connect(function(player, data)
    local store = self._store
    store:SetAsync(tostring(player.UserId), data)
end)
"""
    assert any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code))
    )


def test_connections_tracked_for_teardown_are_not_loop_leaks():
    """`table.insert(self._connections, x.Pressed:Connect(...))` inside a loop
    keeps every connection; the `:Disconnect(` is in the teardown method,
    which is where cleanup belongs — not in the loop that created them."""
    agent = RobloxAuditAgent()
    code = """
for index, action in actions do
    table.insert(
        self._connections,
        (action :: any).Pressed:Connect(function()
            use(index)
        end)
    )
end

function Controller.destroy(self)
    for _, connection in self._connections do
        connection:Disconnect()
    end
    table.clear(self._connections)
end
"""
    assert not any(
        "inside a loop" in i for i in _issues(agent._audit_connection_leaks(code))
    )


def test_connections_collected_but_never_disconnected_are_still_leaks():
    agent = RobloxAuditAgent()
    code = """
for _, id in ids do
    table.insert(self._connections, workspace.Changed:Connect(function()
        refresh(id)
    end))
end
"""
    assert any(
        "inside a loop" in i for i in _issues(agent._audit_connection_leaks(code))
    )


# --- Codex review of PR #65 -------------------------------------------------


def test_a_shim_that_also_does_its_own_work_is_not_a_shim():
    """Forwarding the payload does not excuse everything else in the body:
    `giveDailyReward(player)` is work this handler really does, and it stays
    as spammable and as unvalidated as the check says."""
    agent = RobloxAuditAgent()
    code = """
rewardEvent.OnServerEvent:Connect(function(player, payload)
    giveDailyReward(player)
    local handler = self._payloadHandler
    if handler ~= nil then
        handler(player, payload)
    end
end)
"""
    issues = _issues(agent._audit_remote_validation(code))
    assert any("type/shape validation" in i for i in issues)
    assert any("rate limiting" in i for i in issues)


def test_an_unrelated_module_cannot_vouch_for_a_same_named_validator():
    """Two reachable modules define `isValid`. The one actually called does
    not validate, so the finding stands — `Other.isValid` is not evidence."""
    agent = RobloxAuditAgent()
    code = """
actionEvent.OnServerEvent:Connect(function(player, payload)
    if not Contract.isValid(payload) then
        return
    end
    local last = lastAt[player]
    if last and os.clock() - last < 1 then
        return
    end
    lastAt[player] = os.clock()
    apply(player, payload)
end)
"""
    imported = """
local Other = {}
function Other.isValid(value)
    return typeof(value) == "number"
end
local Contract = {}
function Contract.isValid(payload)
    return payload ~= nil
end
"""
    assert any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code, imported))
    )

    validating = """
local Other = {}
function Other.isValid(value)
    return value ~= nil
end
local Contract = {}
function Contract.isValid(payload)
    return typeof(payload) == "table"
end
"""
    assert not any(
        "type/shape validation" in i
        for i in _issues(agent._audit_remote_validation(code, validating))
    )


def test_an_unrelated_teardown_does_not_vouch_for_a_loop_local_connection():
    """A `:Disconnect(` somewhere in the file is not enough — it has to name
    the same storage. Here it disconnects a menu handler, while each loop
    iteration drops its own connection on the floor."""
    agent = RobloxAuditAgent()
    code = """
local menuConnection = menu.Closed:Connect(onClose)
menuConnection:Disconnect()

function refresh()
    for _, part in ipairs(parts) do
        local connection = part.Touched:Connect(onTouch)
    end
end
"""
    assert any(
        "inside a loop" in i for i in _issues(agent._audit_connection_leaks(code))
    )
