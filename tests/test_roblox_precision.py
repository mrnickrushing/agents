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
