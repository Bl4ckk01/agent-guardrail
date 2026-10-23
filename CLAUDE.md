# Agent Guardrail — Multi-Agent Project Guide

An automatic safety guardrail for **Claude Code**, **OpenAI Codex / ChatGPT**, **Google Antigravity**, **Cursor**, and **Grok Build** (`agent-guardrail`).

Prevents destructive actions (`rm -rf`, force push, database drops, format operations) and access to sensitive files (`.env`, secrets, paths outside workspace) in the background via system hooks and rule interceptors with ultra-low latency.

---

## 1. Quick Install: `install.py`

Configure your preferred coding agent(s):
```bash
# Configure all 5 platforms automatically
python install.py

# Configure specific platform(s)
python install.py --claude
python install.py --cursor
python install.py --antigravity
python install.py --codex
python install.py --grok
python install.py --mcp

# Global installation into home directories (~/)
python install.py --global
```

---

## 2. How to Use: `/guardrail` Command

When native lifecycle hooks are active (Claude Code, Codex, Antigravity), do not execute manual Python verification scripts before routine commands.

Users activate protection simply by typing:
```text
/guardrail
```
*(or `/guardrail on`, or `$guardrail` on Codex).*

Once activated:
1. Lifecycle hooks (`UserPromptSubmit`, `PreToolUse`) intercept every user request and tool call (`Bash`, `PowerShell`, `Write`, `Edit`, `write_to_file`, `replace_file_content`).
2. Safe read-only actions (`ls`, `git status`, test runners) pass silently with zero delay.
3. Sensitive actions (`ask_user`) prompt for human approval (native interactive dialog on Claude Code and Antigravity, confirmation in chat on Codex, Cursor, Grok).
4. Prohibited actions (`block`) are halted immediately. Never attempt to bypass a block by rephrasing, splitting, or obfuscating the command.

---

## 3. Slash & Skill Commands

- `/guardrail` or `/guardrail on`: Enable protection for the current session.
- `/guardrail start`: Launch background daemon and enable protection.
- `/guardrail off`: Temporarily disable protection for manual maintenance.
- `/guardrail stop`: Stop background daemon and disable protection.
- `/guardrail status`: View active status, configured backend, and daemon health.
- `/guardrail reload`: Dynamically reload `policy.yaml` rules without restarting the session.
- `/guardrail check <cmd>`: Dry-run evaluate `<cmd>` (verdict, risk score, preview) without running it.
- `/guardrail why`: Explain the most recent blocked or confirmation-required action from the audit log.
- `/guardrail doctor`: Run unified diagnostics (policy, audit hash chain, skill sync, daemons).

---

## 4. Unit Tests

Run the test suites (135 tests total):
```bash
python -B tests/test_check_action.py
python -B tests/test_guardrail_hook.py
python -B tests/test_mcp_server.py
```
