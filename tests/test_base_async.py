import asyncio
import sys
import types
from types import SimpleNamespace

from agents.base import BaseAgent


def _fake_openai_module(sync_factory, async_factory):
    return types.SimpleNamespace(OpenAI=sync_factory, AsyncOpenAI=async_factory)


def _response(message, model="fake-model"):
    usage = SimpleNamespace(model_dump=lambda: {"total_tokens": 3})
    choice = SimpleNamespace(message=message, finish_reason="stop")
    return SimpleNamespace(choices=[choice], usage=usage, model=model)


class _SyncOpenAIClient:
    instances = []

    def __init__(self, *args, **kwargs):
        self.calls = []
        self.closed = False
        self.__class__.instances.append(self)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **payload):
        self.calls.append(payload)
        return _response(SimpleNamespace(content="ok", tool_calls=[]))

    def close(self):
        self.closed = True


class _AsyncOpenAIClient:
    instances = []

    def __init__(self, *args, **kwargs):
        self.calls = []
        self.closed = False
        self.__class__.instances.append(self)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
        self._responses = [
            _response(
                SimpleNamespace(
                    content="",
                    tool_calls=[
                        SimpleNamespace(
                            id="tool-1",
                            function=SimpleNamespace(
                                name="lookup", arguments='{"value": "abc"}'
                            ),
                            model_dump=lambda: {"id": "tool-1"},
                        )
                    ],
                )
            ),
            _response(SimpleNamespace(content="done", tool_calls=[])),
        ]

    async def create(self, **payload):
        self.calls.append(payload)
        return self._responses.pop(0)

    async def aclose(self):
        self.closed = True


class _PersistedAgent(BaseAgent):
    system_prompt = "persist"


class _AsyncToolAgent(BaseAgent):
    system_prompt = "async"
    max_tool_rounds = 4

    def _define_tools(self):
        return [
            {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            }
        ]

    def _bind_tool_handlers(self):
        async def lookup(value: str):
            return {"echo": value}

        return {"lookup": lookup}


def test_openai_client_is_reused_and_closed(monkeypatch):
    _SyncOpenAIClient.instances.clear()
    _AsyncOpenAIClient.instances.clear()
    monkeypatch.setitem(
        sys.modules,
        "openai",
        _fake_openai_module(_SyncOpenAIClient, _AsyncOpenAIClient),
    )

    agent = _PersistedAgent(provider="openai", api_key="test-key")
    agent.run("first")
    agent.run("second")
    assert len(_SyncOpenAIClient.instances) == 1

    agent.close()
    assert _SyncOpenAIClient.instances[0].closed is True


def test_conversation_store_persists_history_across_instances(tmp_path, monkeypatch):
    _SyncOpenAIClient.instances.clear()
    _AsyncOpenAIClient.instances.clear()
    monkeypatch.setitem(
        sys.modules,
        "openai",
        _fake_openai_module(_SyncOpenAIClient, _AsyncOpenAIClient),
    )
    store_path = tmp_path / "conversations.db"

    first = _PersistedAgent(
        provider="openai",
        api_key="test-key",
        conversation_store_path=str(store_path),
    )
    first.run("first", conversation_id="session-1")
    first.close()

    second = _PersistedAgent(
        provider="openai",
        api_key="test-key",
        conversation_store_path=str(store_path),
    )
    second.run("second", conversation_id="session-1")
    messages = _SyncOpenAIClient.instances[-1].calls[-1]["messages"]

    assert any(
        message.get("content") == "first"
        for message in messages
        if isinstance(message, dict)
    )
    assert any(
        message.get("content") == "ok"
        for message in messages
        if isinstance(message, dict)
    )


def test_async_run_supports_async_tools_and_per_call_round_limit(monkeypatch):
    _SyncOpenAIClient.instances.clear()
    _AsyncOpenAIClient.instances.clear()
    monkeypatch.setitem(
        sys.modules,
        "openai",
        _fake_openai_module(_SyncOpenAIClient, _AsyncOpenAIClient),
    )

    async def run():
        agent = _AsyncToolAgent(provider="openai", api_key="test-key")
        result = await agent.run_async("use tool", max_tool_rounds=1)
        await agent.aclose()
        return result

    result = asyncio.run(run())
    assert result.content == "done"
    assert len(_AsyncOpenAIClient.instances) == 1
    assert _AsyncOpenAIClient.instances[0].closed is True


def test_call_with_retries_async_uses_asyncio_sleep(monkeypatch):
    agent = BaseAgent()
    calls = {"count": 0}
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    def flaky():
        calls["count"] += 1
        if calls["count"] == 1:
            exc = type("APIStatusError", (Exception,), {})("boom")
            exc.status_code = 503
            raise exc
        return "ok"

    monkeypatch.setattr("agents.base.asyncio.sleep", fake_sleep)
    assert asyncio.run(agent._call_with_retries_async(flaky)) == "ok"
    assert sleeps == [2]
