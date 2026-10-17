#!/usr/bin/env python3
"""Model Context Protocol (MCP) Server for Agent Guardrail.

Exposes agent-guardrail safety policies (policy.yaml) and the multi-tier
decision engine (check_action.py) as a standard MCP server over stdio.

Supported Clients:
  - Claude Desktop
  - Google Antigravity
  - Cursor (Composer & Agent)
  - OpenAI Codex / ChatGPT MCP clients
  - Zed, VS Code Copilot, and any MCP 2024-11-05 compliant host.

Usage:
  python mcp_server.py                # Run stdio MCP server (standard mode)
  python mcp_server.py --test         # Execute self-tests and protocol validation
  python mcp_server.py --export-config # Print configuration snippets for Claude, Cursor, Antigravity
  python mcp_server.py --install-cursor # Create or update .cursor/mcp.json in workspace
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Configure robust UTF-8 I/O for cross-platform stdio communication
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stdin and hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure repo root is in python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import check_action as ca
import daemon_manager as dm

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "agent-guardrail"
SERVER_VERSION = "1.0.0"


def _log(msg: str) -> None:
    """Log diagnostic information to stderr.
    
    IMPORTANT: In MCP stdio transport, stdout is reserved strictly
    for JSON-RPC 2.0 messages. Any stdout pollution will corrupt the protocol.
    """
    print(f"[{SERVER_NAME}] {msg}", file=sys.stderr, flush=True)


class MCPServer:
    """Model Context Protocol server implementing stdio JSON-RPC 2.0."""

    def __init__(self, root_dir: Path | None = None) -> None:
        self.root_dir = root_dir or ROOT_DIR
        self.policy_path = self.root_dir / "policy.yaml"
        self._ensure_policy_loaded()

    def _ensure_policy_loaded(self) -> None:
        try:
            ca.load_policy(self.policy_path)
        except Exception as exc:
            _log(f"Warning: Failed to load policy at {self.policy_path}: {exc}")

    # =========================================================================
    # Protocol Handlers
    # =========================================================================

    def handle_message(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Process a JSON-RPC 2.0 request or notification and return response."""
        if not isinstance(request, dict):
            return self._make_error(None, -32600, "Invalid Request: expected JSON object")

        msg_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        # Handle notifications (requests without an 'id')
        if msg_id is None:
            self._handle_notification(method, params)
            return None

        if not isinstance(method, str):
            return self._make_error(msg_id, -32600, "Invalid Request: 'method' must be a string")

        try:
            if method == "initialize":
                return self._make_result(msg_id, self._handle_initialize(params))
            if method == "ping":
                return self._make_result(msg_id, {})
            if method == "tools/list":
                return self._make_result(msg_id, self._handle_tools_list(params))
            if method == "tools/call":
                return self._make_result(msg_id, self._handle_tools_call(params))
            if method == "resources/list":
                return self._make_result(msg_id, self._handle_resources_list(params))
            if method == "resources/read":
                return self._make_result(msg_id, self._handle_resources_read(params))
            if method == "prompts/list":
                return self._make_result(msg_id, self._handle_prompts_list(params))
            if method == "prompts/get":
                return self._make_result(msg_id, self._handle_prompts_get(params))

            return self._make_error(msg_id, -32601, f"Method not found: '{method}'")
        except Exception as exc:
            _log(f"Error handling method '{method}': {exc}\n{traceback.format_exc()}")
            return self._make_error(msg_id, -32603, f"Internal error: {type(exc).__name__}: {exc}")

    def _handle_notification(self, method: str | None, params: dict[str, Any]) -> None:
        """Handle client notifications (no response returned)."""
        if method == "notifications/initialized":
            _log("Client initialized connection successfully.")
        elif method == "notifications/cancelled":
            _log(f"Client cancelled operation: {params}")
        else:
            _log(f"Received notification: {method}")

    def _make_result(self, msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _make_error(self, msg_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": msg_id, "error": err}

    # =========================================================================
    # Initialize
    # =========================================================================

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        client_info = params.get("clientInfo", {})
        _log(f"Client connected: {client_info.get('name', 'unknown')} v{client_info.get('version', 'unknown')}")
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    # =========================================================================
    # Tools
    # =========================================================================

    def _handle_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "check_action",
                    "description": (
                        "Verify whether a shell command or agent action is permitted under the active "
                        "agent-guardrail policy. Returns a decision ('proceed', 'ask_user', 'block') "
                        "along with matched rules and detailed rationale."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "description": "The command line or natural language action to verify (e.g., 'rm -rf build', 'git status', 'pip install requests').",
                            },
                            "backend": {
                                "type": "string",
                                "description": "Optional decision backend ('rules', 'd1', 'clm', 'jev'). Defaults to policy setting.",
                                "enum": ["rules", "d1", "clm", "jev"],
                            },
                            "explain": {
                                "type": "boolean",
                                "description": "Whether to include detailed rule breakdown and model reasoning.",
                                "default": True,
                            },
                        },
                        "required": ["action"],
                    },
                },
                {
                    "name": "check_batch_actions",
                    "description": (
                        "Verify a list of actions or commands in a single call. Returns individual decisions "
                        "and an aggregated overall verdict based on the most severe violation."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "actions": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of command line strings or action descriptions to verify.",
                            },
                            "backend": {
                                "type": "string",
                                "description": "Optional decision backend ('rules', 'd1', 'clm', 'jev').",
                                "enum": ["rules", "d1", "clm", "jev"],
                            },
                            "explain": {
                                "type": "boolean",
                                "description": "Whether to include detailed explanations for each item.",
                                "default": False,
                            },
                        },
                        "required": ["actions"],
                    },
                },
                {
                    "name": "get_guardrail_status",
                    "description": "Inspect active guardrail backend, running daemons, and rule count.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
                {
                    "name": "list_active_rules",
                    "description": "List all active block, ask, proceed, and path-specific rules loaded from policy.yaml.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
                {
                    "name": "reload_policy",
                    "description": "Reload policy.yaml from disk without restarting the MCP server.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
            ]
        }

    def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}

        if not isinstance(arguments, dict):
            return {
                "content": [{"type": "text", "text": "Error: 'arguments' must be an object"}],
                "isError": True,
            }

        if name == "check_action":
            return self._tool_check_action(arguments)
        if name == "check_batch_actions":
            return self._tool_check_batch_actions(arguments)
        if name == "get_guardrail_status":
            return self._tool_get_guardrail_status(arguments)
        if name == "list_active_rules":
            return self._tool_list_active_rules(arguments)
        if name == "reload_policy":
            return self._tool_reload_policy(arguments)

        return {
            "content": [{"type": "text", "text": f"Error: Unknown tool '{name}'"}],
            "isError": True,
        }

    def _tool_check_action(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action")
        if not action or not isinstance(action, str):
            return {
                "content": [{"type": "text", "text": "Error: 'action' is required and must be a non-empty string."}],
                "isError": True,
            }

        backend = args.get("backend")
        explain = args.get("explain", True)

        decision_obj = ca.decide(action, backend_name=backend)

        data = {
            "action": action,
            "decision": decision_obj.decision,
            "allowed": decision_obj.decision == "proceed",
            "requires_confirmation": decision_obj.decision == "ask_user",
            "blocked": decision_obj.decision == "block",
            "backend": decision_obj.backend,
            "matched_rules": list(decision_obj.rules.matched),
            "explanation": decision_obj.explain() if explain else None,
            "error": decision_obj.error,
        }

        return {
            "content": [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}],
            "isError": False,
        }

    def _tool_check_batch_actions(self, args: dict[str, Any]) -> dict[str, Any]:
        actions = args.get("actions")
        if not isinstance(actions, list) or not actions:
            return {
                "content": [{"type": "text", "text": "Error: 'actions' must be a non-empty list of strings."}],
                "isError": True,
            }

        backend = args.get("backend")
        explain = args.get("explain", False)

        results = []
        decisions = []

        for item in actions:
            action_str = str(item)
            dec_obj = ca.decide(action_str, backend_name=backend)
            decisions.append(dec_obj.decision)
            results.append({
                "action": action_str,
                "decision": dec_obj.decision,
                "allowed": dec_obj.decision == "proceed",
                "requires_confirmation": dec_obj.decision == "ask_user",
                "blocked": dec_obj.decision == "block",
                "matched_rules": list(dec_obj.rules.matched),
                "explanation": dec_obj.explain() if explain else None,
            })

        overall = ca.most_severe(*decisions) if decisions else "proceed"

        summary = {
            "total": len(results),
            "proceed": sum(1 for d in decisions if d == "proceed"),
            "ask_user": sum(1 for d in decisions if d == "ask_user"),
            "block": sum(1 for d in decisions if d == "block"),
        }

        output = {
            "overall_decision": overall,
            "overall_allowed": overall == "proceed",
            "summary": summary,
            "results": results,
        }

        return {
            "content": [{"type": "text", "text": json.dumps(output, indent=2, ensure_ascii=False)}],
            "isError": False,
        }

    def _tool_get_guardrail_status(self, _args: dict[str, Any]) -> dict[str, Any]:
        st = dm.get_status()
        report = dm.format_status_report()

        data = {
            "active_backend": st.get("active_backend"),
            "active_ready": st.get("active_ready"),
            "manual_start": st.get("manual_start"),
            "backends": st.get("backends"),
            "policy_path": str(self.policy_path),
            "human_readable_report": report,
        }

        return {
            "content": [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}],
            "isError": False,
        }

    def _tool_list_active_rules(self, _args: dict[str, Any]) -> dict[str, Any]:
        self._ensure_policy_loaded()

        path_rules_data = []
        for pr in ca._PATH_RULES:
            path_rules_data.append({
                "name": pr.name,
                "path": pr.path,
                "decision": pr.decision,
                "all_commands": pr.all_commands,
                "commands": pr.commands,
            })

        data = {
            "policy_file": str(self.policy_path),
            "counts": {
                "built_in_block": len(ca.BLOCK_RULES),
                "built_in_ask": len(ca.ASK_RULES),
                "built_in_proceed": len(ca.PROCEED_RULES),
                "custom_block": len(ca._CUSTOM_BLOCK),
                "custom_ask": len(ca._CUSTOM_ASK),
                "custom_proceed": len(ca._CUSTOM_PROCEED),
                "path_rules": len(ca._PATH_RULES),
            },
            "custom_block_rules": [name for name, _ in ca._CUSTOM_BLOCK],
            "custom_ask_rules": [name for name, _ in ca._CUSTOM_ASK],
            "custom_proceed_rules": [name for name, _ in ca._CUSTOM_PROCEED],
            "path_rules": path_rules_data,
        }

        return {
            "content": [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}],
            "isError": False,
        }

    def _tool_reload_policy(self, _args: dict[str, Any]) -> dict[str, Any]:
        ca.load_policy(self.policy_path)
        data = {
            "reloaded": True,
            "policy_file": str(self.policy_path),
            "custom_block_rules": len(ca._CUSTOM_BLOCK),
            "custom_ask_rules": len(ca._CUSTOM_ASK),
            "custom_proceed_rules": len(ca._CUSTOM_PROCEED),
            "path_rules": len(ca._PATH_RULES),
            "message": "Policy reloaded successfully from disk.",
        }
        return {
            "content": [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}],
            "isError": False,
        }

    # =========================================================================
    # Resources
    # =========================================================================

    def _handle_resources_list(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {
            "resources": [
                {
                    "uri": "guardrail://policy",
                    "name": "Active Policy Configuration",
                    "description": "Raw contents of policy.yaml currently enforcing safety rules.",
                    "mimeType": "application/yaml",
                },
                {
                    "uri": "guardrail://status",
                    "name": "Live Guardrail Health & Status",
                    "description": "Health status of backends, local models, ports, and daemons.",
                    "mimeType": "application/json",
                },
                {
                    "uri": "guardrail://rules",
                    "name": "Active Guardrail Rules Catalog",
                    "description": "Structured catalog of all active block, ask, proceed, and path rules.",
                    "mimeType": "application/json",
                },
            ]
        }

    def _handle_resources_read(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        if not uri:
            raise ValueError("'uri' parameter is required for resources/read")

        if uri == "guardrail://policy":
            if self.policy_path.is_file():
                text = self.policy_path.read_text(encoding="utf-8")
            else:
                text = "# policy.yaml not found on disk"
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/yaml",
                        "text": text,
                    }
                ]
            }

        if uri == "guardrail://status":
            st = dm.get_status()
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(st, indent=2, ensure_ascii=False),
                    }
                ]
            }

        if uri == "guardrail://rules":
            tool_res = self._tool_list_active_rules({})
            raw_text = tool_res["content"][0]["text"]
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": raw_text,
                    }
                ]
            }

        raise ValueError(f"Unknown resource URI: '{uri}'")

    # =========================================================================
    # Prompts
    # =========================================================================

    def _handle_prompts_list(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {
            "prompts": [
                {
                    "name": "guardrail-pre-execution-check",
                    "description": "Prompt template asking the model to verify safety of a command before running it.",
                    "arguments": [
                        {
                            "name": "command",
                            "description": "The command line or task to evaluate.",
                            "required": True,
                        }
                    ],
                },
                {
                    "name": "guardrail-safety-guidelines",
                    "description": "System safety instructions summarizing BLOCK, ASK_USER, and PROCEED criteria.",
                    "arguments": [],
                },
            ]
        }

    def _handle_prompts_get(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}

        if name == "guardrail-pre-execution-check":
            cmd = arguments.get("command", "")
            return {
                "description": "Pre-execution security audit instruction",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                f"You are bound by Agent Guardrail policy.\n"
                                f"Before executing this command: `{cmd}`\n\n"
                                f"Use the `check_action` tool to verify the command:\n"
                                f"- If the decision is 'block': REFUSE immediately with an explanation.\n"
                                f"- If the decision is 'ask_user': Request explicit user approval first.\n"
                                f"- If the decision is 'proceed': You may proceed with execution."
                            ),
                        },
                    }
                ],
            }

        if name == "guardrail-safety-guidelines":
            return {
                "description": "Summary of active safety guardrail guidelines",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                "# Agent Guardrail Safety Policy Summary\n\n"
                                "1. 🚫 BLOCK (Strictly Denied):\n"
                                "   - Recursive deletions (`rm -rf`, `del /s`, `rmdir /s`)\n"
                                "   - Force git mutations (`git push --force`, deleting remote branches)\n"
                                "   - Database drops (`DROP TABLE`, `TRUNCATE TABLE`, unbounded deletes)\n"
                                "   - System format or raw disk operations\n"
                                "   - Secret/credential exposures (.env, id_rsa, tokens, passwords)\n\n"
                                "2. ⚠️ ASK USER (Explicit Human Confirmation Required):\n"
                                "   - Modifying configuration files (.env, docker-compose.yml, package.json)\n"
                                "   - Running containers (docker run, docker exec)\n"
                                "   - Cloud modifications (kubectl apply, terraform apply)\n"
                                "   - Global package installations (npm -g, pip --user)\n\n"
                                "3. ⚡ PROCEED (Permitted Silently):\n"
                                "   - Read-only inspection (ls, cat, grep, git status, git diff)\n"
                                "   - Test suites and linters (pytest, npm test, ruff check)\n"
                                "   - Routine source code edits, refactors, and adding tests."
                            ),
                        },
                    }
                ],
            }

        raise ValueError(f"Unknown prompt name: '{name}'")

    # =========================================================================
    # Transport Loop (stdio)
    # =========================================================================

    def run_stdio(self) -> None:
        """Run the server loop reading newline-delimited JSON-RPC from stdin."""
        _log(f"Server starting on stdio (protocol {MCP_PROTOCOL_VERSION})...")

        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                request = json.loads(line_str)
            except json.JSONDecodeError as exc:
                err_resp = self._make_error(None, -32700, f"Parse error: {exc}")
                self._send_response(err_resp)
                continue

            # Batch request support
            if isinstance(request, list):
                responses = []
                for req_item in request:
                    resp_item = self.handle_message(req_item)
                    if resp_item is not None:
                        responses.append(resp_item)
                if responses:
                    self._send_raw(json.dumps(responses, ensure_ascii=False))
                continue

            response = self.handle_message(request)
            if response is not None:
                self._send_response(response)

    def _send_response(self, response: dict[str, Any]) -> None:
        out = json.dumps(response, ensure_ascii=False)
        self._send_raw(out)

    def _send_raw(self, text: str) -> None:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


# =============================================================================
# Helper Utilities & Self-Test
# =============================================================================

def get_config_snippets() -> dict[str, Any]:
    """Return ready-to-use configuration JSON for supported MCP clients."""
    py_exe = sys.executable
    server_script = str(ROOT_DIR / "mcp_server.py")
    cwd = str(ROOT_DIR)

    return {
        "claude_desktop": {
            "mcpServers": {
                "agent-guardrail": {
                    "command": py_exe,
                    "args": [server_script],
                    "cwd": cwd,
                }
            }
        },
        "cursor": {
            "mcpServers": {
                "agent-guardrail": {
                    "command": py_exe,
                    "args": [server_script],
                }
            }
        },
        "antigravity": {
            "mcpServers": {
                "agent-guardrail": {
                    "command": py_exe,
                    "args": [server_script],
                    "cwd": cwd,
                }
            }
        },
        "generic": {
            "command": py_exe,
            "args": [server_script],
            "cwd": cwd,
        },
    }


def install_cursor_config(workspace_dir: Path | None = None) -> tuple[bool, str]:
    """Create or merge .cursor/mcp.json in the target workspace."""
    base = workspace_dir or ROOT_DIR
    cursor_dir = base / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    mcp_file = cursor_dir / "mcp.json"

    data: dict[str, Any] = {"mcpServers": {}}
    if mcp_file.is_file():
        try:
            data = json.loads(mcp_file.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {"mcpServers": {}}

    servers = data.setdefault("mcpServers", {})
    servers["agent-guardrail"] = {
        "command": sys.executable,
        "args": [str(ROOT_DIR / "mcp_server.py")],
    }

    mcp_file.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True, f"✔ Successfully configured MCP server in {mcp_file}"


def run_self_test() -> bool:
    """Run simulated end-to-end JSON-RPC exchanges to verify protocol compliance."""
    _log("Starting internal protocol self-test...")
    server = MCPServer()

    # 1. Initialize test
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "clientInfo": {"name": "self-test-client", "version": "1.0"},
        },
    }
    resp = server.handle_message(init_req)
    assert resp and resp.get("result", {}).get("serverInfo", {}).get("name") == SERVER_NAME, f"Init failed: {resp}"
    _log("  ✔ initialize handshake PASSED")

    # 2. Ping test
    ping_resp = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_resp and ping_resp.get("result") == {}, f"Ping failed: {ping_resp}"
    _log("  ✔ ping PASSED")

    # 3. Notification test (must return None)
    notif_resp = server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert notif_resp is None, "Notification must not produce response"
    _log("  ✔ notification handling PASSED")

    # 4. Tools list test
    tools_resp = server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    tools = tools_resp.get("result", {}).get("tools", [])
    tool_names = {t["name"] for t in tools}
    expected = {"check_action", "check_batch_actions", "get_guardrail_status", "list_active_rules", "reload_policy"}
    assert expected.issubset(tool_names), f"Missing tools in {tool_names}"
    _log(f"  ✔ tools/list PASSED ({len(tool_names)} tools discovered)")

    # 5. Tool call: check_action safe (proceed)
    safe_call = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "check_action", "arguments": {"action": "git status"}},
    }
    safe_res = server.handle_message(safe_call)
    content = json.loads(safe_res["result"]["content"][0]["text"])
    assert content["decision"] == "proceed", f"Expected proceed, got: {content}"
    assert content["allowed"] is True
    _log("  ✔ tools/call (safe action: git status -> proceed) PASSED")

    # 6. Tool call: check_action block (dangerous command)
    block_call = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "check_action", "arguments": {"action": "rm -rf /"}},
    }
    block_res = server.handle_message(block_call)
    content_b = json.loads(block_res["result"]["content"][0]["text"])
    assert content_b["decision"] == "block", f"Expected block, got: {content_b}"
    assert content_b["allowed"] is False
    assert content_b["blocked"] is True
    _log("  ✔ tools/call (destructive action: rm -rf / -> block) PASSED")

    # 7. Tool call: check_action ask_user (sensitive config)
    ask_call = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "check_action", "arguments": {"action": "docker run -it ubuntu bash"}},
    }
    ask_res = server.handle_message(ask_call)
    content_a = json.loads(ask_res["result"]["content"][0]["text"])
    assert content_a["decision"] == "ask_user", f"Expected ask_user, got: {content_a}"
    assert content_a["requires_confirmation"] is True
    _log("  ✔ tools/call (sensitive action: docker run -> ask_user) PASSED")

    # 8. Tool call: check_batch_actions
    batch_call = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "check_batch_actions",
            "arguments": {
                "actions": ["ls", "docker compose up", "rm -rf /var"],
            },
        },
    }
    batch_res = server.handle_message(batch_call)
    batch_data = json.loads(batch_res["result"]["content"][0]["text"])
    assert batch_data["overall_decision"] == "block", f"Batch overall mismatch: {batch_data}"
    assert batch_data["summary"]["total"] == 3
    assert batch_data["summary"]["proceed"] == 1
    assert batch_data["summary"]["ask_user"] == 1
    assert batch_data["summary"]["block"] == 1
    _log("  ✔ tools/call (batch verification) PASSED")

    # 9. Tool call: get_guardrail_status
    st_call = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "get_guardrail_status", "arguments": {}},
    }
    st_res = server.handle_message(st_call)
    st_data = json.loads(st_res["result"]["content"][0]["text"])
    assert "active_backend" in st_data
    _log("  ✔ tools/call (get_guardrail_status) PASSED")

    # 10. Resources list and read
    res_list = server.handle_message({"jsonrpc": "2.0", "id": 9, "method": "resources/list"})
    resources = res_list.get("result", {}).get("resources", [])
    assert len(resources) >= 3
    _log(f"  ✔ resources/list PASSED ({len(resources)} resources)")

    res_read = server.handle_message({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "resources/read",
        "params": {"uri": "guardrail://policy"},
    })
    res_content = res_read.get("result", {}).get("contents", [{}])[0].get("text", "")
    assert len(res_content) > 0
    _log("  ✔ resources/read (guardrail://policy) PASSED")

    # 11. Prompts list and get
    prompts_list = server.handle_message({"jsonrpc": "2.0", "id": 11, "method": "prompts/list"})
    prompts = prompts_list.get("result", {}).get("prompts", [])
    assert len(prompts) >= 2
    _log(f"  ✔ prompts/list PASSED ({len(prompts)} prompts)")

    prompt_get = server.handle_message({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "prompts/get",
        "params": {"name": "guardrail-pre-execution-check", "arguments": {"command": "git push -f"}},
    })
    msg_text = prompt_get.get("result", {}).get("messages", [{}])[0].get("content", {}).get("text", "")
    assert "git push -f" in msg_text
    _log("  ✔ prompts/get (guardrail-pre-execution-check) PASSED")

    # 12. Error handling test
    err_res = server.handle_message({"jsonrpc": "2.0", "id": 13, "method": "non_existent_method"})
    assert err_res and "error" in err_res and err_res["error"]["code"] == -32601
    _log("  ✔ error handling (unknown method -> -32601) PASSED")

    _log("🎉 ALL PROTOCOL SELF-TESTS PASSED!")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Agent Guardrail MCP Server")
    parser.add_argument("--test", action="store_true", help="Run protocol validation self-tests")
    parser.add_argument("--export-config", action="store_true", help="Print MCP client configuration snippets")
    parser.add_argument("--install-cursor", action="store_true", help="Configure .cursor/mcp.json in workspace")

    args = parser.parse_args()

    if args.test:
        ok = run_self_test()
        return 0 if ok else 1

    if args.export_config:
        snippets = get_config_snippets()
        print(json.dumps(snippets, indent=2, ensure_ascii=False))
        return 0

    if args.install_cursor:
        ok, msg = install_cursor_config()
        print(msg)
        return 0 if ok else 1

    # Standard mode: run stdio loop
    server = MCPServer()
    try:
        server.run_stdio()
    except KeyboardInterrupt:
        _log("Server stopped by user interrupt.")
    except Exception as exc:
        _log(f"Fatal error in stdio server: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
