#!/usr/bin/env python3
"""Fail-closed entry point for the agents' lifecycle hooks.

Agents treat a hook that crashes as a non-blocking error and run the tool call anyway. If
guardrail_hook.py cannot even be imported (syntax error, missing dependency, broken install), that
would silently switch protection off. This launcher uses only the standard library: whatever goes wrong
while loading or running the guardrail, a tool call asks for confirmation (Claude Code, Antigravity) or
is denied (Codex), with the reason, instead of passing unchecked.

Usage (hook command):  python hook_launcher.py --host claude|codex|antigravity
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ICON = "\U0001F6E1️"
_ASK_HOSTS = ("claude", "antigravity", "agy", "gemini")


def fail_closed(raw: str, host: str, reason: str) -> tuple[dict | None, int]:
    """(stdout JSON, exit code) for an event the guardrail could not evaluate."""
    message = f"{ICON} Guardrail could not check this action ({reason}). Confirm only if you trust it, and run /guardrail doctor."
    try:
        event = json.loads(raw) if raw.strip() else {}
    except ValueError:
        event = None
    if not isinstance(event, dict):
        # Unreadable input: exit code 2 makes the agent stop and show stderr
        sys.stderr.write(message + "\n")
        return None, 2
    name = str(event.get("hook_event_name") or ("PreToolUse" if ("tool_name" in event or "toolCall" in event) else ""))
    if name == "PreToolUse" or "toolCall" in event:
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "ask", "reason": message}, 0
        decision = "ask" if host in _ASK_HOSTS else "deny"
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                       "permissionDecisionReason": message}}, 0
    if name == "UserPromptSubmit" and host == "claude":
        return {"systemMessage": message}, 0
    return None, 0


def main(argv: list[str]) -> int:
    host = argv[argv.index("--host") + 1].lower() if "--host" in argv[:-1] else "codex"
    raw = sys.stdin.buffer.read().decode("utf-8-sig", errors="replace")  # tolerate a BOM some shells add
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import guardrail_hook
    except BaseException as exc:  # noqa: BLE001 - any load failure must fail closed
        out, code = fail_closed(raw, host, f"guardrail failed to load: {type(exc).__name__}: {exc}")
    else:
        try:
            return guardrail_hook.run_hook(raw, host)
        except BaseException as exc:  # noqa: BLE001
            out, code = fail_closed(raw, host, f"internal error: {type(exc).__name__}: {exc}")
    if out is not None:
        sys.stdout.buffer.write(json.dumps(out, ensure_ascii=False).encode("utf-8"))
        sys.stdout.buffer.flush()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
