"""ReAct (reason / act / observe) loop — the shared primitive every specialist runs.

Flow per turn:
  1. reason: provider.complete(messages, tools) -> LLMResponse
  2. if it returned tool_calls: act (execute each via the tool registry), observe
     (append results to history as 'tool' messages), loop again.
  3. if it returned plain content (no tool_calls): that is the final answer -> stop.

Safety rails: max_steps prevents a runaway model that never stops calling tools; a tool
that raises records an error observation but lets the model recover; tool results are
TRUNCATED to `max_tool_result_chars` before being appended to history so a huge payload
(e.g. the 437KB base64 blob of a protected file) cannot blow the LLM context window.

The tool registry is anything with execute(name, arguments) -> JSON-serializable result
(maps cleanly to an MCPClient wrapper).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from agent.llm.provider import LLMResponse

log = logging.getLogger(__name__)

DEFAULT_MAX_STEPS = 25
# Cap each tool result appended to the conversation. A protected/packed binary's strings
# or disassembly can be hundreds of KB; without this the next reasoning step overflows
# the model's context window. The full result stays in Step.tool_result for reporting.
DEFAULT_MAX_TOOL_RESULT_CHARS = 8000


@dataclass
class Step:
    """One act/observe cycle within the loop."""
    tool_name: str
    tool_args: dict
    tool_result: object = None
    tool_error: bool = False


@dataclass
class ReActResult:
    final_text: str = ""
    steps: list[Step] = field(default_factory=list)
    truncated: bool = False


def react_loop(
    *,
    provider,
    registry,
    messages: list[dict],
    tools: list[dict],
    max_steps: int = DEFAULT_MAX_STEPS,
    max_tool_result_chars: int = DEFAULT_MAX_TOOL_RESULT_CHARS,
    system: str | None = None,
) -> ReActResult:
    """Run the ReAct loop to completion (or truncation).

    `messages` is treated as the initial conversation; a `system` prompt, if given,
    is prepended once. The list is copied, not mutated in place.
    """
    history: list[dict] = list(messages)
    if system:
        history = [{"role": "system", "content": system}] + history

    result = ReActResult()
    steps_taken = 0

    while True:
        response: LLMResponse = provider.complete(history, tools=tools)

        # No tool calls -> the model produced its final textual answer.
        if not response.tool_calls:
            result.final_text = response.content or ""
            return result

        # Execute each requested tool call in order.
        for tc in response.tool_calls:
            if steps_taken >= max_steps:
                result.truncated = True
                result.final_text = (
                    f"[truncated: reached max_steps={max_steps} of tool calls without a final answer]"
                )
                return result
            steps_taken += 1

            # Record the assistant's tool-call request in history.
            history.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [{
                    "id": tc.id or f"call_{steps_taken}",
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }],
            })

            tool_result: object
            tool_error = False
            try:
                tool_result = registry.execute(tc.name, tc.arguments)
            except Exception as exc:  # noqa: BLE001
                tool_result = {"error": str(exc)}
                tool_error = True
                log.warning("tool %s raised: %s", tc.name, exc)

            result.steps.append(Step(
                tool_name=tc.name, tool_args=tc.arguments,
                tool_result=tool_result, tool_error=tool_error,
            ))

            # Observe: append the tool result for the next reasoning step. Truncate huge
            # payloads so a protected binary's multi-hundred-KB strings/disasm cannot
            # overflow the model context window. The full result is kept in Step above.
            content = json.dumps(tool_result) if not isinstance(tool_result, str) else tool_result
            if len(content) > max_tool_result_chars:
                content = (content[:max_tool_result_chars]
                           + f"\n...[truncated: {len(content) - max_tool_result_chars} more chars]")
            history.append({
                "role": "tool",
                "tool_call_id": tc.id or f"call_{steps_taken}",
                "name": tc.name,
                "content": content,
            })
