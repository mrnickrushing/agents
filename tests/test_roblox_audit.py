import json

from agents.roblox_audit import RobloxAuditAgent, _block_end, _strip_luau_noise


def _issues(result):
    return [finding["issue"] for finding in result.get("findings", [])]


def test_remote_handler_trusting_client_supplied_target_is_detected():
    code = """
GiveReward.OnServerEvent:Connect(function(player, targetUserId, amount)
    local target = Players:GetPlayerByUserId(targetUserId)
    target.leaderstats.Coins.Value += amount
end)
"""
    issues = _issues(RobloxAuditAgent()._audit_remote_validation(code))
    assert any("client-supplied data instead of relying on the trusted" in issue for issue in issues)


def test_remote_handler_acting_on_trusted_player_argument_is_not_flagged_for_identity():
    code = """
GiveReward.OnServerEvent:Connect(function(player, amount)
    assert(typeof(amount) == "number")
    player.leaderstats.Coins.Value += amount
end)
"""
    issues = _issues(RobloxAuditAgent()._audit_remote_validation(code))
    assert not any("relying on the trusted" in issue for issue in issues)


def test_rojo_project_mapping_server_source_into_replicated_storage_is_critical():
    project_json = json.dumps({
        "tree": {
            "$className": "DataModel",
            "ReplicatedStorage": {"Server": {"$path": "src/server"}},
        }
    })
    result = RobloxAuditAgent()._review_rojo_project_structure(project_json)
    assert any(f["severity"] == "CRITICAL" for f in result["findings"])


def test_rojo_project_with_server_source_under_serverscriptservice_is_clean():
    project_json = json.dumps({
        "tree": {
            "$className": "DataModel",
            "ServerScriptService": {"Server": {"$path": "src/server"}},
            "ReplicatedStorage": {"Shared": {"$path": "src/shared"}},
        }
    })
    result = RobloxAuditAgent()._review_rojo_project_structure(project_json)
    assert result["findings"] == []


def test_datastore_call_without_pcall_is_flagged():
    code = """
local data = store:GetAsync(key)
data.coins = data.coins + 10
store:SetAsync(key, data)
"""
    issues = _issues(RobloxAuditAgent()._audit_datastore_usage(code))
    assert any("not wrapped in an enclosing pcall" in issue for issue in issues)
    assert any("read-modify-write" in issue for issue in issues)


def test_datastore_call_wrapped_in_pcall_with_update_and_bindtoclose_is_clean():
    code = """
game:BindToClose(function()
    for _, player in Players:GetPlayers() do
        pcall(function()
            store:UpdateAsync(key(player), function(old)
                return merge(old, snapshot(player))
            end)
        end)
    end
end)
"""
    result = RobloxAuditAgent()._audit_datastore_usage(code)
    assert result["findings"] == []


def test_datastore_method_name_in_a_comment_is_not_flagged():
    code = "-- remember to call store:GetAsync(key) inside a pcall before shipping"
    result = RobloxAuditAgent()._audit_datastore_usage(code)
    assert result["findings"] == []
    assert result["note"] == "No DataStore method calls found in this snippet"


def test_process_receipt_without_decision_enum_or_idempotency_is_flagged():
    code = """
MarketplaceService.ProcessReceipt = function(receiptInfo)
    local player = Players:GetPlayerByUserId(receiptInfo.PlayerId)
    player.leaderstats.Coins.Value += 100
    return true
end
"""
    issues = _issues(RobloxAuditAgent()._review_receipt_processing(code))
    assert any("ProductPurchaseDecision" in issue for issue in issues)
    assert any("PurchaseId" in issue for issue in issues)
    assert any("pcall" in issue for issue in issues)


def test_process_receipt_with_decision_idempotency_and_pcall_is_clean():
    code = """
MarketplaceService.ProcessReceipt = function(receiptInfo)
    local player = Players:GetPlayerByUserId(receiptInfo.PlayerId)
    local ok = pcall(function()
        grantIfNotAlreadyGranted(player, receiptInfo.PurchaseId)
    end)
    if not ok then
        return Enum.ProductPurchaseDecision.NotProcessedYet
    end
    return Enum.ProductPurchaseDecision.PurchaseGranted
end
"""
    result = RobloxAuditAgent()._review_receipt_processing(code)
    assert result["findings"] == []


def test_frame_signal_nested_in_player_added_without_disconnect_is_flagged():
    code = """
Players.PlayerAdded:Connect(function(player)
    player.CharacterAdded:Connect(function(char)
        RunService.Heartbeat:Connect(function()
            char:GetPivot()
        end)
    end)
end)
"""
    issues = _issues(RobloxAuditAgent()._audit_connection_leaks(code))
    assert any("per-frame signal" in issue for issue in issues)


def test_per_player_signal_alone_in_player_added_is_not_flagged():
    code = """
Players.PlayerAdded:Connect(function(player)
    player.CharacterAdded:Connect(function(char)
        char:GetPivot()
    end)
end)
"""
    result = RobloxAuditAgent()._audit_connection_leaks(code)
    assert result["findings"] == []


def test_connect_after_a_startup_loop_is_not_treated_as_nested_inside_it():
    code = """
for _, player in Players:GetPlayers() do
    doSomething(player)
end

RunService.Heartbeat:Connect(function(deltaTime)
    tick(deltaTime)
end)
"""
    result = RobloxAuditAgent()._audit_connection_leaks(code)
    assert result["findings"] == []


def test_connect_actually_inside_loop_body_is_flagged():
    code = """
for _, item in items do
    item.Changed:Connect(function()
        refresh(item)
    end)
end
"""
    issues = _issues(RobloxAuditAgent()._audit_connection_leaks(code))
    assert any("created inside a loop body" in issue for issue in issues)


def test_unyielding_while_true_loop_is_flagged():
    code = """
while true do
    print("tick")
end
"""
    issues = _issues(RobloxAuditAgent()._audit_performance_patterns(code))
    assert any("while true do" in issue for issue in issues)


def test_while_true_loop_with_task_wait_is_clean():
    code = """
while true do
    task.wait(1)
    print("tick")
end
"""
    result = RobloxAuditAgent()._audit_performance_patterns(code)
    assert not any("while true do" in f["issue"] for f in result["findings"])


def test_task_wait_is_not_flagged_as_deprecated():
    code = "task.wait(1)"
    result = RobloxAuditAgent()._audit_performance_patterns(code)
    assert result["findings"] == []


def test_bare_wait_is_flagged_as_deprecated():
    code = "wait(1)"
    issues = _issues(RobloxAuditAgent()._audit_performance_patterns(code))
    assert any("wait() is deprecated" in issue for issue in issues)


def test_localplayer_writing_leaderstats_is_flagged():
    code = """
local player = Players.LocalPlayer
player.leaderstats.Coins.Value += 100
"""
    issues = _issues(RobloxAuditAgent()._audit_server_authority(code))
    assert any("leaderstats value is written directly from client-side code" in issue for issue in issues)


def test_server_only_code_without_localplayer_is_not_flagged():
    code = """
local player = playerFromRemote
player.leaderstats.Coins.Value += 100
"""
    result = RobloxAuditAgent()._audit_server_authority(code)
    assert result["findings"] == []


# ── Block-boundary edge cases (regression coverage for review feedback) ───


def test_if_expression_does_not_consume_the_enclosing_end():
    code = """
Players.PlayerAdded:Connect(function(player)
    local greeting = if player.Name == "Bob" then "hi bob" else "hi"
    print(greeting)
end)

SomethingAfter:Connect(function()
    shouldNotBeIncludedInThePlayerAddedBody()
end)
"""
    stripped = _strip_luau_noise(code)
    start = stripped.find("function(player)") + len("function(player)")
    body = stripped[start : _block_end(stripped, start)]
    assert "SomethingAfter" not in body


def test_datastore_call_after_a_closed_pcall_is_still_flagged():
    code = """
pcall(function()
    doSomethingUnrelated()
end)
local data = store:GetAsync(key)
"""
    issues = _issues(RobloxAuditAgent()._audit_datastore_usage(code))
    assert any("not wrapped in an enclosing pcall" in issue for issue in issues)


def test_bare_pcall_without_anonymous_function_still_protects_its_call():
    code = "local ok, data = pcall(store.GetAsync, store, key)"
    result = RobloxAuditAgent()._audit_datastore_usage(code)
    assert not any("not wrapped in an enclosing pcall" in f["issue"] for f in result["findings"])


def test_unvalidated_handler_is_flagged_even_when_a_sibling_handler_validates():
    code = """
Trusted.OnServerEvent:Connect(function(player, amount)
    assert(typeof(amount) == "number")
    player.leaderstats.Coins.Value += amount
end)

Untrusted.OnServerEvent:Connect(function(player, amount)
    player.leaderstats.Coins.Value += amount
end)
"""
    result = RobloxAuditAgent()._audit_remote_validation(code)
    validation_findings = [f for f in result["findings"] if "type/shape validation" in f["issue"]]
    assert len(validation_findings) == 1


def test_signal_wait_inside_while_true_is_treated_as_yielding():
    code = """
while true do
    RunService.Heartbeat:Wait()
    tick()
end
"""
    result = RobloxAuditAgent()._audit_performance_patterns(code)
    assert not any("while true do" in f["issue"] for f in result["findings"])
