"""Tests for agent.mcp_client — the stdio MCP client wrapper.

The real transport spawns a subprocess (mcp stdio_client) and a ClientSession; for
unit tests we inject a fake async session exposing list_tools()/call_tool().
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.mcp_client import MCPClient, Tool, ToolResult, build_server_params  # noqa: E402


class FakeSession:
    """Minimal async stand-in for an mcp ClientSession."""

    def __init__(self, tools=None, results=None):
        self._tools = tools or []
        self._results = results or {}
        self.calls = []

    async def list_tools(self):
        return type("R", (), {"tools": list(self._tools)})

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        res = self._results.get(
            name, {"content": [{"type": "text", "text": "ok"}], "is_error": False}
        )
        return type("R", (), res)


def make_tool(name, schema=None):
    return Tool(name=name, description=f"tool {name}", input_schema=schema or {})


async def test_list_tools_returns_tool_objects():
    sess = FakeSession(tools=[make_tool("decompile_function"), make_tool("list_functions")])
    client = MCPClient(sess)
    tools = await client.list_tools()
    names = [t.name for t in tools]
    assert "decompile_function" in names and "list_functions" in names


async def test_call_tool_forwards_name_and_args_returns_result():
    sess = FakeSession(
        results={
            "list_functions": {
                "content": [{"type": "text", "text": "['main','check']"}],
                "is_error": False,
            }
        }
    )
    client = MCPClient(sess)
    r = await client.call_tool("list_functions", {"filter": "main*"})
    assert isinstance(r, ToolResult)
    assert r.is_error is False
    assert "main" in r.text
    assert sess.calls[0] == ("list_functions", {"filter": "main*"})


async def test_call_tool_surfaces_is_error():
    sess = FakeSession(
        results={
            "decompile_function": {
                "content": [{"type": "text", "text": "address not in range"}],
                "is_error": True,
            }
        }
    )
    client = MCPClient(sess)
    r = await client.call_tool("decompile_function", {"addr": "0x999"})
    assert r.is_error is True
    assert "address not in range" in r.text


async def test_call_tool_missing_content_is_not_error_by_default():
    sess = FakeSession(results={"x": {"is_error": False}})
    client = MCPClient(sess)
    r = await client.call_tool("x", {})
    assert r.is_error is False
    assert r.text == ""


def test_build_server_params_from_config():
    cfg = {"command": "python", "args": ["-m", "mcp_servers.static.server"]}
    params = build_server_params(cfg)
    assert params.command == "python"
    assert list(params.args) == ["-m", "mcp_servers.static.server"]


def test_build_server_params_extra_env():
    cfg = {
        "command": "python",
        "args": ["-m", "mcp_servers.x"],
        "env": {"GHIDRA_HOME": "/opt/ghidra"},
    }
    params = build_server_params(cfg)
    assert params.command == "python"
    assert params.env is not None
    assert params.env.get("GHIDRA_HOME") == "/opt/ghidra"
