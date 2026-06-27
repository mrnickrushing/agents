"""
Base agent class — all RushingTech agents inherit from this.

Provides the OpenAI-compatible interface, conversation management,
and tool/function calling conventions.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional


class BaseAgent:
    """
    OpenAI-compatible agent base class.

    Usage:
        agent = SecurityAuditAgent(api_key="sk-...")
        response = agent.run("Audit this Express app for Helmet misconfigurations")
        print(response.content)

    Or use the OpenAI chat completions interface:
        messages = agent.format_messages("Audit this Express app")
        # Send messages to any OpenAI-compatible endpoint
    """

    name: str = "base_agent"
    description: str = "Base agent — override in subclass"
    system_prompt: str = "You are a helpful assistant."
    model: str = "gpt-4o"
    temperature: float = 0.3
    max_tokens: int = 4096

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        base_url: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or self.model
        self.temperature = temperature if temperature is not None else self.temperature
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self._conversation: List[Dict[str, str]] = []
        self._tools: List[Dict[str, Any]] = tools or self._define_tools()
        self._tool_handlers: Dict[str, Callable] = self._bind_tool_handlers()

    # ── OpenAI-compatible message formatting ──────────────────────────

    def format_messages(self, user_input: str, context: Optional[str] = None) -> List[Dict[str, str]]:
        """Format the current conversation into OpenAI chat completion messages."""
        messages = [{"role": "system", "content": self.system_prompt}]
        if context:
            messages.append({"role": "system", "content": f"Context:\n{context}"})
        messages.extend(self._conversation)
        messages.append({"role": "user", "content": user_input})
        return messages

    def format_tools(self) -> Optional[List[Dict[str, Any]]]:
        """Return tools in OpenAI function calling format."""
        if not self._tools:
            return None
        return [{"type": "function", "function": t} for t in self._tools]

    def format_payload(self, user_input: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a complete OpenAI chat completion payload.
        Ready to POST to /v1/chat/completions.
        """
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": self.format_messages(user_input, context),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        tools = self.format_tools()
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        return payload

    # ── Execution ──────────────────────────────────────────────────────

    def run(self, user_input: str, context: Optional[str] = None) -> AgentResponse:
        """
        Execute the agent with a user input string.
        Uses the OpenAI Python SDK if available, otherwise returns the payload.
        """
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            payload = self.format_payload(user_input, context)

            # Remove 'model' from payload since client.chat.completions.create takes it separately
            response = client.chat.completions.create(**payload)

            # Process tool calls if present
            choice = response.choices[0]
            assistant_message = choice.message

            # Handle tool calls
            if assistant_message.tool_calls:
                result = self._execute_tool_calls(assistant_message.tool_calls)
                # Re-run with tool results
                self._conversation.append({"role": "user", "content": user_input})
                self._conversation.append({"role": "assistant", "content": assistant_message.content or "", "tool_calls": [tc.model_dump() for tc in assistant_message.tool_calls]})
                for tool_result in result:
                    self._conversation.append({"role": "tool", "content": json.dumps(tool_result), "tool_call_id": tool_result["tool_call_id"]})

                # Second call with tool results
                second_payload = {
                    "model": self.model,
                    "messages": self._conversation,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                }
                response = client.chat.completions.create(**second_payload)
                choice = response.choices[0]
                assistant_message = choice.message

            self._conversation.append({"role": "user", "content": user_input})
            self._conversation.append({"role": "assistant", "content": assistant_message.content or ""})

            return AgentResponse(
                content=assistant_message.content or "",
                model=response.model,
                usage=response.usage.model_dump() if response.usage else None,
                raw=response,
            )

        except ImportError:
            # No OpenAI SDK — return the payload for manual sending
            payload = self.format_payload(user_input, context)
            return AgentResponse(
                content=f"[No OpenAI SDK installed] Payload ready for POST to {self.base_url}/chat/completions",
                model=self.model,
                usage=None,
                raw=payload,
            )

    # ── Tool execution ────────────────────────────────────────────────

    def _execute_tool_calls(self, tool_calls: List[Any]) -> List[Dict[str, Any]]:
        """Execute tool calls returned by the model."""
        results = []
        for tc in tool_calls:
            func_name = tc.function.name
            func_args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments, str) else tc.function.arguments
            handler = self._tool_handlers.get(func_name)
            if handler:
                try:
                    output = handler(**func_args)
                    results.append({"tool_call_id": tc.id, "result": output})
                except Exception as e:
                    results.append({"tool_call_id": tc.id, "error": str(e)})
            else:
                results.append({"tool_call_id": tc.id, "error": f"Unknown tool: {func_name}"})
        return results

    def _define_tools(self) -> List[Dict[str, Any]]:
        """Override in subclass to define OpenAI function tools."""
        return []

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        """Override in subclass to map tool names to handler functions."""
        return {}

    # ── Conversation management ───────────────────────────────────────

    def reset(self) -> None:
        """Clear conversation history."""
        self._conversation = []

    @property
    def history(self) -> List[Dict[str, str]]:
        """Return conversation history."""
        return list(self._conversation)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.model}>"


class AgentResponse:
    """Standardized response object from any RushingTech agent."""

    def __init__(
        self,
        content: str,
        model: Optional[str] = None,
        usage: Optional[Dict[str, int]] = None,
        raw: Any = None,
    ):
        self.content = content
        self.model = model
        self.usage = usage
        self.raw = raw

    def __str__(self) -> str:
        return self.content

    def __repr__(self) -> str:
        return f"<AgentResponse model={self.model} tokens={self.usage}>"
