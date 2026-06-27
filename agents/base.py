"""
Base agent class — supports OpenAI and Anthropic APIs.

Provides unified interface for both providers, conversation management,
and tool/function calling conventions.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional


class BaseAgent:
    """
    Multi-provider agent base class (OpenAI + Anthropic).

    Usage:
        # OpenAI
        agent = SecurityAuditAgent(api_key="sk-...", provider="openai")
        response = agent.run("Audit this Express app")
        
        # Anthropic (Claude)
        ui_agent = UIGenerationAgent(api_key="sk-ant-...", provider="anthropic")
        response = ui_agent.run("Create a dashboard card")
        
        # Multi-turn conversation
        response = ui_agent.run("Now make it clickable", conversation_id="session-123")
    """

    name: str = "base_agent"
    description: str = "Base agent — override in subclass"
    system_prompt: str = "You are a helpful assistant."
    model: str = "gpt-5"
    temperature: float = 0.3
    max_tokens: int = 4096

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: str = "openai",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        base_url: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ):
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(f"{self.provider.upper()}_API_KEY")
        self.model = model or self.model
        self.temperature = temperature if temperature is not None else self.temperature
        
        # Provider-specific defaults
        if self.provider == "anthropic":
            self.base_url = base_url or os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
            if not self.model.startswith("claude-"):
                self.model = "claude-sonnet-4-6"  # Default Claude model
        else:
            self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        
        # Conversation storage — supports multi-turn with conversation_id
        self._conversations: Dict[str, List[Dict[str, Any]]] = {}
        self._current_conversation_id: Optional[str] = None
        
        self._tools: List[Dict[str, Any]] = tools or self._define_tools()
        self._tool_handlers: Dict[str, Callable] = self._bind_tool_handlers()

    # ── Conversation Management ─────────────────────────────────────

    def _get_conversation(self, conversation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get or create conversation by ID."""
        cid = conversation_id or "default"
        if cid not in self._conversations:
            self._conversations[cid] = []
        self._current_conversation_id = cid
        return self._conversations[cid]

    def reset(self, conversation_id: Optional[str] = None) -> None:
        """Clear conversation history."""
        cid = conversation_id or "default"
        self._conversations[cid] = []

    @property
    def history(self) -> List[Dict[str, Any]]:
        """Return current conversation history."""
        return list(self._get_conversation())

    # ── Message Formatting (Unified) ────────────────────────────────

    def format_messages(
        self, 
        user_input: str, 
        context: Optional[str] = None,
        conversation_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Format messages in provider-native format."""
        conversation = self._get_conversation(conversation_id)
        
        if self.provider == "anthropic":
            # Anthropic format: requires system as separate param
            messages = list(conversation)
            messages.append({"role": "user", "content": user_input})
            return messages
        else:
            # OpenAI format: system included in messages array
            messages = [{"role": "system", "content": self.system_prompt}]
            if context:
                messages.append({"role": "system", "content": f"Context:\n{context}"})
            messages.extend(conversation)
            messages.append({"role": "user", "content": user_input})
            return messages

    def format_tools(self) -> Optional[List[Dict[str, Any]]]:
        """Return tools in provider-native format."""
        if not self._tools:
            return None
        return self._tools

    # ── Execution ─────────────────────────────────────────────────────

    def run(
        self, 
        user_input: str, 
        context: Optional[str] = None,
        conversation_id: Optional[str] = None,
        images: Optional[List[Dict[str, Any]]] = None
    ) -> AgentResponse:
        """Execute agent with user input (supports both providers)."""
        
        conversation = self._get_conversation(conversation_id)
        
        try:
            if self.provider == "anthropic":
                return self._run_anthropic(user_input, conversation, context, images)
            else:
                return self._run_openai(user_input, conversation, context)
                
        except ImportError as e:
            return AgentResponse(
                content=f"[SDK not installed for {self.provider}] {str(e)}\nInstall: {'pip install anthropic' if self.provider == 'anthropic' else 'pip install openai'}",
                model=self.model,
                usage=None,
                raw=None,
            )

    def _run_openai(
        self, 
        user_input: str, 
        conversation: List[Dict[str, Any]], 
        context: Optional[str] = None
    ) -> AgentResponse:
        """Run using OpenAI API."""
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        
        # Build messages with system prompt
        messages = [{"role": "system", "content": self.system_prompt}]
        if context:
            messages.append({"role": "system", "content": f"Context:\n{context}"})
        messages.extend(conversation)
        messages.append({"role": "user", "content": user_input})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        tools = self.format_tools()
        if tools:
            payload["tools"] = [{"type": "function", "function": t} for t in tools]
            payload["tool_choice"] = "auto"

        response = client.chat.completions.create(**payload)
        choice = response.choices[0]
        assistant_message = choice.message

        # Handle tool calls
        if assistant_message.tool_calls:
            tool_results = self._execute_tool_calls(assistant_message.tool_calls)
            
            # Append user and assistant messages
            conversation.append({"role": "user", "content": user_input})
            conversation.append({
                "role": "assistant", 
                "content": assistant_message.content or "",
                "tool_calls": [tc.model_dump() for tc in assistant_message.tool_calls]
            })
            
            # Append tool results
            for tool_result in tool_results:
                conversation.append({
                    "role": "tool", 
                    "content": json.dumps(tool_result),
                    "tool_call_id": tool_result["tool_call_id"]
                })
            
            # Second call with tool results
            second_payload = {
                "model": self.model,
                "messages": messages + conversation,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
            response = client.chat.completions.create(**second_payload)
            choice = response.choices[0]
            assistant_message = choice.message

        conversation.append({"role": "user", "content": user_input})
        conversation.append({"role": "assistant", "content": assistant_message.content or ""})

        return AgentResponse(
            content=assistant_message.content or "",
            model=response.model,
            usage=response.usage.model_dump() if response.usage else None,
            raw=response,
        )

    def _run_anthropic(
        self, 
        user_input: str, 
        conversation: List[Dict[str, Any]], 
        context: Optional[str] = None,
        images: Optional[List[Dict[str, Any]]] = None
    ) -> AgentResponse:
        """Run using Anthropic (Claude) API."""
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key, base_url=self.base_url)
        
        # Build user message — can include text + images
        user_content: List[Dict[str, Any]] = [{"type": "text", "text": user_input}]
        
        if images:
            for img in images:
                user_content.append({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": img["media_type"],
                        "data": img["data"]
                    }
                })
        
        messages = list(conversation)
        messages.append({"role": "user", "content": user_content})
        
        # Add context to system prompt if provided
        system_prompt = self.system_prompt
        if context:
            system_prompt = f"{system_prompt}\n\nContext:\n{context}"
        
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        tools = self.format_tools()
        if tools:
            payload["tools"] = tools
        
        response = client.messages.create(**payload)
        
        # Handle tool use
        tool_blocks = [b for b in response.content if b.type == "tool_use"]
        text_content = "".join(b.text for b in response.content if b.type == "text")
        
        if tool_blocks:
            # Execute tools
            tool_calls = []
            for block in tool_blocks:
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input
                })
            
            tool_results = self._execute_tool_calls_anthropic(tool_calls)
            
            # Append to conversation
            conversation.append({"role": "user", "content": user_content})
            conversation.append({
                "role": "assistant",
                "content": response.content
            })
            
            # Append tool results
            for result in tool_results:
                conversation.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": result["tool_use_id"],
                            "content": json.dumps(result["result"])
                        }
                    ]
                })
            
            # Second call with tool results
            response = client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=messages + conversation,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                tools=tools if tools else None,
            )
            text_content = "".join(b.text for b in response.content if b.type == "text")
        
        conversation.append({"role": "user", "content": user_content})
        conversation.append({"role": "assistant", "content": response.content})
        
        return AgentResponse(
            content=text_content,
            model=response.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
            raw=response,
        )

    # ── Tool Execution ───────────────────────────────────────────────

    def _execute_tool_calls(self, tool_calls: List[Any]) -> List[Dict[str, Any]]:
        """Execute OpenAI-style tool calls."""
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

    def _execute_tool_calls_anthropic(self, tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute Anthropic-style tool calls."""
        results = []
        for tc in tool_calls:
            func_name = tc["name"]
            func_args = tc["arguments"]
            handler = self._tool_handlers.get(func_name)
            if handler:
                try:
                    output = handler(**func_args)
                    results.append({"tool_use_id": tc["id"], "result": output})
                except Exception as e:
                    results.append({"tool_use_id": tc["id"], "error": str(e)})
            else:
                results.append({"tool_use_id": tc["id"], "error": f"Unknown tool: {func_name}"})
        return results

    def _define_tools(self) -> List[Dict[str, Any]]:
        """Override in subclass to define tool schemas."""
        return []

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        """Override in subclass to map tool names to handlers."""
        return {}

    # ── Utility ──────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider={self.provider} model={self.model}>"


class AgentResponse:
    """Standardized response object from any agent."""
    
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
