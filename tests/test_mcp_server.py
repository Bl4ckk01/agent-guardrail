#!/usr/bin/env python3
"""Unit tests for mcp_server.py (Model Context Protocol)."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import mcp_server as ms


class TestMCPProtocolBasics(unittest.TestCase):
    def setUp(self):
        self.server = ms.MCPServer()

    def test_initialize(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": ms.MCP_PROTOCOL_VERSION,
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }
        res = self.server.handle_message(req)
        self.assertIsNotNone(res)
        self.assertEqual(res.get("id"), 1)
        self.assertEqual(res.get("jsonrpc"), "2.0")
        result = res.get("result", {})
        self.assertEqual(result.get("protocolVersion"), ms.MCP_PROTOCOL_VERSION)
        self.assertEqual(result.get("serverInfo", {}).get("name"), "agent-guardrail")
        self.assertIn("tools", result.get("capabilities", {}))
        self.assertIn("resources", result.get("capabilities", {}))
        self.assertIn("prompts", result.get("capabilities", {}))

    def test_ping(self):
        req = {"jsonrpc": "2.0", "id": "req-ping", "method": "ping"}
        res = self.server.handle_message(req)
        self.assertEqual(res, {"jsonrpc": "2.0", "id": "req-ping", "result": {}})

    def test_notifications_produce_no_response(self):
        req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        res = self.server.handle_message(req)
        self.assertIsNone(res)

    def test_method_not_found(self):
        req = {"jsonrpc": "2.0", "id": 42, "method": "non_existent_rpc"}
        res = self.server.handle_message(req)
        self.assertIsNotNone(res)
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32601)

    def test_invalid_request_format(self):
        res = self.server.handle_message("not a dict")  # type: ignore
        self.assertEqual(res["error"]["code"], -32600)

        res2 = self.server.handle_message({"id": 1, "method": 12345})  # type: ignore
        self.assertEqual(res2["error"]["code"], -32600)


class TestMCPTools(unittest.TestCase):
    def setUp(self):
        self.server = ms.MCPServer()

    def test_tools_list(self):
        req = {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
        res = self.server.handle_message(req)
        tools = res.get("result", {}).get("tools", [])
        names = {t["name"] for t in tools}
        self.assertIn("check_action", names)
        self.assertIn("check_batch_actions", names)
        self.assertIn("get_guardrail_status", names)
        self.assertIn("list_active_rules", names)
        self.assertIn("reload_policy", names)

    def test_check_action_proceed(self):
        req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "check_action", "arguments": {"action": "git status"}},
        }
        res = self.server.handle_message(req)
        self.assertFalse(res.get("result", {}).get("isError"))
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["decision"], "proceed")
        self.assertTrue(content["allowed"])
        self.assertFalse(content["blocked"])
        self.assertFalse(content["requires_confirmation"])

    def test_check_action_block(self):
        req = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "check_action", "arguments": {"action": "rm -rf /"}},
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["decision"], "block")
        self.assertFalse(content["allowed"])
        self.assertTrue(content["blocked"])

    def test_check_action_ask_user(self):
        req = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "check_action", "arguments": {"action": "docker run -d redis"}},
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["decision"], "ask_user")
        self.assertTrue(content["requires_confirmation"])
        self.assertFalse(content["allowed"])

    def test_check_action_missing_argument(self):
        req = {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "check_action", "arguments": {}},
        }
        res = self.server.handle_message(req)
        self.assertTrue(res["result"]["isError"])

    def test_check_batch_actions(self):
        req = {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "check_batch_actions",
                "arguments": {"actions": ["ls", "git status", "rm -rf /tmp/data"]},
            },
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["overall_decision"], "block")
        self.assertFalse(content["overall_allowed"])
        self.assertEqual(content["summary"]["total"], 3)
        self.assertEqual(content["summary"]["proceed"], 2)
        self.assertEqual(content["summary"]["block"], 1)

    def test_get_guardrail_status(self):
        req = {
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {"name": "get_guardrail_status", "arguments": {}},
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertIn("active_backend", content)
        self.assertIn("backends", content)

    def test_list_active_rules(self):
        req = {
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/call",
            "params": {"name": "list_active_rules", "arguments": {}},
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertIn("counts", content)
        self.assertIn("custom_block_rules", content)
        self.assertGreater(content["counts"]["built_in_block"], 0)

    def test_reload_policy(self):
        req = {
            "jsonrpc": "2.0",
            "id": 18,
            "method": "tools/call",
            "params": {"name": "reload_policy", "arguments": {}},
        }
        res = self.server.handle_message(req)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(content["reloaded"])


class TestMCPResources(unittest.TestCase):
    def setUp(self):
        self.server = ms.MCPServer()

    def test_resources_list(self):
        req = {"jsonrpc": "2.0", "id": 20, "method": "resources/list"}
        res = self.server.handle_message(req)
        resources = res.get("result", {}).get("resources", [])
        uris = {r["uri"] for r in resources}
        self.assertIn("guardrail://policy", uris)
        self.assertIn("guardrail://status", uris)
        self.assertIn("guardrail://rules", uris)

    def test_resources_read_policy(self):
        req = {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "resources/read",
            "params": {"uri": "guardrail://policy"},
        }
        res = self.server.handle_message(req)
        contents = res.get("result", {}).get("contents", [])
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["mimeType"], "application/yaml")
        self.assertIn("custom_block_rules", contents[0]["text"])

    def test_resources_read_invalid_uri(self):
        req = {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "resources/read",
            "params": {"uri": "guardrail://unknown"},
        }
        res = self.server.handle_message(req)
        self.assertIn("error", res)


class TestMCPPrompts(unittest.TestCase):
    def setUp(self):
        self.server = ms.MCPServer()

    def test_prompts_list(self):
        req = {"jsonrpc": "2.0", "id": 30, "method": "prompts/list"}
        res = self.server.handle_message(req)
        prompts = res.get("result", {}).get("prompts", [])
        names = {p["name"] for p in prompts}
        self.assertIn("guardrail-pre-execution-check", names)
        self.assertIn("guardrail-safety-guidelines", names)

    def test_prompts_get(self):
        req = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "prompts/get",
            "params": {
                "name": "guardrail-pre-execution-check",
                "arguments": {"command": "git push --force origin main"},
            },
        }
        res = self.server.handle_message(req)
        messages = res.get("result", {}).get("messages", [])
        self.assertEqual(len(messages), 1)
        self.assertIn("git push --force origin main", messages[0]["content"]["text"])


class TestMCPHelpers(unittest.TestCase):
    def test_export_config(self):
        snippets = ms.get_config_snippets()
        self.assertIn("claude_desktop", snippets)
        self.assertIn("cursor", snippets)
        self.assertIn("antigravity", snippets)
        self.assertIn("generic", snippets)

    def test_install_cursor_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            ok, msg = ms.install_cursor_config(tmp_path)
            self.assertTrue(ok)
            cursor_mcp = tmp_path / ".cursor" / "mcp.json"
            self.assertTrue(cursor_mcp.is_file())
            data = json.loads(cursor_mcp.read_text(encoding="utf-8"))
            self.assertIn("agent-guardrail", data.get("mcpServers", {}))


if __name__ == "__main__":
    unittest.main()
