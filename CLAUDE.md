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

# Global installation into home directories (~/)
python install.py --global
```

---

## 2. How to Use: `/guardrail` Command

Never execute manual Python verification scripts (`python check_action.py "..."`) before commands.

Users activate protection simply by typing:
```
/guardrail
```
*(or `/guardrail on`, or `$guardrail` on Codex).*

Once activated:
1. Lifecycle hooks (`UserPromptSubmit`, `PreToolUse`) intercept every user request and tool call (`Bash`, `PowerShell`, `Write`, `Edit`, `write_to_file`, `replace_file_content`).
2. Safe read-only actions (`ls`, `git status`, test runners) pass silently with zero delay.
3. Sensitive actions (`ask_user`) prompt for human approval (native interactive dialog on Claude Code and Antigravity, confirmation in chat on Codex, Cursor, Grok).
4. Prohibited actions (`block`) are halted immediately.

---

## 3. Slash & Skill Commands

- `/guardrail` or `/guardrail on`: Enable protection for the current session.
- `/guardrail start`: Launch background daemon and enable protection.
- `/guardrail off`: Temporarily disable protection for manual maintenance.
- `/guardrail stop`: Stop background daemon and disable protection.
- `/guardrail status`: View active status and backend configuration.

---

## 4. Unit Tests

Run the test suites:
```bash
python -m unittest test_check_action -v
python -m unittest test_guardrail_hook -v
```

