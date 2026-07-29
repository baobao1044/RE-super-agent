"""MCP stdio client wrapper.

MCPClient wraps an mcp ClientSession (or a fake for tests) and exposes a small,
synchronous-feeling async API for specialists: list_tools() and call_tool(). It also
provides build_server_params() to construct StdioServerParameters from config, and a
connect() helper that spawns a real subprocess transport (used outside tests).

The result of call_tool is normalized to a plain ToolResult (text + structured content +
is_error) so specialists don't import SDK types.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class Tool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)


@dataclass
class ToolResult:
    text: str = ""
    structured: Any = None
    is_error: bool = False
    raw: Any = None

    @classmethod
    def from_mcp(cls, raw: Any) -> "ToolResult":
        """Normalize an mcp CallToolResult (object with .content / .is_error)."""
        content = getattr(raw, "content", None) or []
        is_error = bool(getattr(raw, "is_error", False))
        text_parts: list[str] = []
        structured: Any = None
        for item in content:
            t = getattr(item, "type", None)
            if t == "text":
                text_parts.append(getattr(item, "text", ""))
            elif t == "structured":
                structured = getattr(item, "structured", None)
            else:
                # fall back to a string repr for unknown content types
                text_parts.append(str(item))
        return cls(text="\n".join(text_parts), structured=structured,
                   is_error=is_error, raw=raw)


class MCPClient:
    """Thin async wrapper over an mcp ClientSession.

    In production a session comes from connect(). In tests a fake session exposing
    async list_tools()/call_tool() is injected directly.
    """

    def __init__(self, session: ClientSession | Any):
        self._session = session

    async def list_tools(self) -> list[Tool]:
        result = await self._session.list_tools()
        raw_tools = getattr(result, "tools", result or [])
        out: list[Tool] = []
        for t in raw_tools:
            out.append(Tool(
                name=getattr(t, "name", "") or "",
                description=getattr(t, "description", "") or "",
                input_schema=getattr(t, "inputSchema", getattr(t, "input_schema", {})) or {},
            ))
        return out

    async def call_tool(self, name: str, arguments: dict | None = None) -> ToolResult:
        raw = await self._session.call_tool(name, arguments or {})
        return ToolResult.from_mcp(raw)


def build_server_params(cfg: dict) -> StdioServerParameters:
    """Build StdioServerParameters from a config mcp.servers.<name> entry."""
    return StdioServerParameters(
        command=cfg["command"],
        args=list(cfg.get("args", [])),
        env=dict(cfg.get("env")) if cfg.get("env") else None,
    )


@asynccontextmanager
async def connect(cfg: dict) -> AsyncIterator[MCPClient]:
    """Spawn a real stdio MCP server subprocess and yield a connected MCPClient.

    Usage:  async with connect(servers["static"]) as client: ...
    """
    params = build_server_params(cfg)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield MCPClient(session)
