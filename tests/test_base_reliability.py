from unittest.mock import patch

import pytest

from agents.base import BaseAgent


def _named_exception(name, status_code=None):
    cls = type(name, (Exception,), {})
    exc = cls("boom")
    exc.status_code = status_code
    return exc


def test_non_retryable_api_status_error_fails_immediately():
    agent = BaseAgent()
    calls = 0

    def fail():
        nonlocal calls
        calls += 1
        raise _named_exception("APIStatusError", 400)

    with pytest.raises(Exception):
        agent._call_with_retries(fail)
    assert calls == 1


def test_server_api_status_error_is_retried():
    agent = BaseAgent()
    calls = 0

    def flaky():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise _named_exception("APIStatusError", 503)
        return "ok"

    with patch("agents.base.time.sleep"):
        assert agent._call_with_retries(flaky) == "ok"
    assert calls == 2


def test_anthropic_message_builder_keeps_images_in_current_turn():
    agent = BaseAgent(provider="anthropic")
    messages = agent._build_anthropic_messages(
        "inspect",
        images=[{"media_type": "image/png", "data": "abc"}],
    )
    assert messages[-1]["content"][0] == {"type": "text", "text": "inspect"}
    assert messages[-1]["content"][1]["type"] == "image"
