---
name: guardrail
description: Activate or manage the safety guardrail for the current session in Claude Code, OpenAI Codex, Google Antigravity, Cursor, and Grok Build via the /guardrail command. Automatically intercepts all shell commands, file edits, and tools in the background.
---

# Agent Safety Guardrail (Claude Code, OpenAI Codex, Antigravity, Cursor, Grok Build)

A multi-tier safety guardrail powered by local contrastive CLM models (`http://localhost:8700`), Liquid AI D1 (`http://localhost:8800`), Jev Cloud API, and offline deterministic security rules (<0.1ms).

## 🚀 Quick Activation: `/guardrail`

You do not need to run manual Python scripts before commands.

Just type in your agent's chat:
```
/guardrail
```
*(or `/guardrail on`, or `$guardrail` on Codex).*

Once activated:
- The guardrail attaches to native lifecycle hooks (`PreToolUse`, `UserPromptSubmit`) or agent rule interceptors.
- Every subsequent prompt and tool action (such as `Bash`, `PowerShell`, `Write`, `Edit`, `write_to_file`, file deletions, and patches) is evaluated **automatically in the background**.
- Read-only commands (such as `ls`, `git status`, `pytest`, `npm test`) pass instantly with zero latency.

## 🛡️ Guardrail Decisions

1. **`proceed`** (Safe, routine action):
   - Executes silently with no disruption to your workflow.
2. **`ask_user`** (Potentially risky action or configuration changes):
   - In **Claude Code**: Triggers native permission dialog (`permissionDecision: "ask"`).
   - In **Google Antigravity**: Prompts for confirmation via native hook (`{"decision": "ask"}`).
   - In **Codex / ChatGPT**: Pauses the action and requests confirmation in chat.
   - In **Cursor / Grok Build**: Prompts user before proceeding with sensitive operations.
3. **`block`** (Destructive or prohibited action):
   - Dangerous operations (like `rm -rf`, force pushes, or deleting `.env`, database tables, and keys) are strictly denied. The agent cannot bypass the block.

## ⚙️ Available Commands

- `/guardrail` or `/guardrail on` (or `$guardrail`): Turn on protection for the current session.
- `/guardrail start` (or `$guardrail start`): Automatically launch the required backend daemon in the background (if `manual_start: false` in `policy.yaml`) and turn on protection.
- `/guardrail off` (or `$guardrail off`): Temporarily turn off protection for manual maintenance.
- `/guardrail stop` (or `$guardrail stop`): Stop background daemons managed by the guardrail and disable protection.
- `/guardrail status` (or `$guardrail status`): Check if the guardrail is active and see live daemon health across D1, CLM, Jev, and Rules.

## 📁 Multi-Agent Architecture

- **Claude Code**: Configured via `.claude/settings.json` and `.claude/skills/agent-guardrail/SKILL.md`.
- **OpenAI Codex**: Configured via `.codex/hooks.json`, `.codex/prompts/agent-guardrail.md`, and `.agents/skills/agent-guardrail/SKILL.md`.
- **Google Antigravity**: Configured via `.agents/hooks.json` and `.agents/skills/guardrail/SKILL.md`.
- **Cursor**: Configured via `.cursor/rules/guardrail.mdc` and `.cursorrules`.
- **Grok Build**: Configured via `.grok/skills/guardrail/SKILL.md` and universal `AGENTS.md`.
- **Core Engine**: `guardrail_hook.py`, `check_action.py`, and `daemon_manager.py` (offline deterministic rules, Liquid AI D1, local CLM, or Jev Cloud API).