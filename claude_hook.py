#!/usr/bin/env python3
"""Claude Code hook entry point (wrapper around guardrail_hook.py)."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import json
import guardrail_hook


def run_guardrail(payload_str: str) -> int:
    """Helper for legacy callers and tests: evaluate payload with active guardrail."""
    try:
        event = json.loads(payload_str) if isinstance(payload_str, str) else dict(payload_str)
    except Exception:
        return 2
    event.setdefault("hook_event_name", "PreToolUse")
    st = guardrail_hook.State()
    sid = str(event.get("session_id") or "_default")
    st.update(sid, active=True)
    out, code = guardrail_hook.handle(event, "claude", st)
    if out and isinstance(out, dict):
        hso = out.get("hookSpecificOutput", {})
        decision = hso.get("permissionDecision") or out.get("decision")
        if decision in ("deny", "ask", "block"):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(guardrail_hook.main(["hook", "--host", "claude"]))

