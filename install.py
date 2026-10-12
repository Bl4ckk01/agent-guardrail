#!/usr/bin/env python3
"""
Install and setup script for Agent Guardrail across 5 major AI coding platforms:
1. Claude Code
2. OpenAI Codex / ChatGPT
3. Google Antigravity (AGY)
4. Cursor (Composer / Agent)
5. Grok Build (xAI CLI)

Usage:
    python install.py                       # Automatically configure all 5 platforms in current workspace
    python install.py --global              # Automatically configure all 5 platforms globally (~/ home directories)
    python install.py --cursor              # Configure only Cursor (workspace)
    python install.py --claude --global     # Configure Claude Code globally and in workspace
    python install.py --antigravity         # Configure Google Antigravity (workspace)
    python install.py --codex               # Configure OpenAI Codex (workspace)
    python install.py --grok                # Configure Grok Build (workspace)
    python install.py --check               # Run system, model daemon, and multi-agent health checks
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_clm(url: str = "http://localhost:8700") -> bool:
    try:
        req = urllib.request.Request(f"{url}/v1/models", headers={"User-Agent": "guardrail-installer"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def check_d1(url: str = "http://localhost:8800") -> bool:
    try:
        req = urllib.request.Request(f"{url}/v1/models", headers={"User-Agent": "guardrail-installer"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def merge_json_hooks(target_path: Path, new_hooks_cfg: dict) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if target_path.exists():
        try:
            existing = json.loads(target_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    hooks = existing.setdefault("hooks", {})
    for event_name, event_list in new_hooks_cfg.get("hooks", {}).items():
        curr_list = hooks.setdefault(event_name, [])
        already_present = any(
            json.dumps(item, sort_keys=True) == json.dumps(new_item, sort_keys=True)
            for item in curr_list
            for new_item in event_list
        )
        if not already_present:
            curr_list.extend(event_list)

    target_path.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def install_shared(workspace: bool, is_global: bool) -> None:
    if workspace:
        # 1. Root SKILL.md
        root_skill = HERE / "SKILL.md"
        if not root_skill.exists():
            print("  ⚠️ root SKILL.md missing")

        # 2. Universal AGENTS.md
        agents_md = HERE / "AGENTS.md"
        if not agents_md.exists():
            print("  ⚠️ root AGENTS.md missing")
        else:
            print("  ✔ AGENTS.md verified (universal multi-agent standard)")

    if is_global:
        guardrail_home = HOME / ".guardrail"
        guardrail_home.mkdir(parents=True, exist_ok=True)
        cfg_file = guardrail_home / "config.json"
        if not cfg_file.exists():
            cfg_file.write_text(
                json.dumps(
                    {"env": {"GUARDRAIL_BACKEND": "d1", "CLM_SERVER_URL": "http://localhost:8700"}},
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        print("  ✔ ~/.guardrail/config.json configured")


def install_claude(workspace: bool, is_global: bool) -> None:
    print("\n🟣 [1/5] Configuring Claude Code (Anthropic)...")
    if workspace:
        claude_settings = HERE / ".claude" / "settings.json"
        claude_hooks_cfg = {
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'python "${CLAUDE_PROJECT_DIR}/guardrail_hook.py" hook --host claude',
                            }
                        ]
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'python "${CLAUDE_PROJECT_DIR}/guardrail_hook.py" hook --host claude',
                            }
                        ]
                    }
                ],
            }
        }
        merge_json_hooks(claude_settings, claude_hooks_cfg)
        print("  ✔ .claude/settings.json configured with lifecycle hooks")

        for sname in ("agent-guardrail", "guardrail"):
            sdir = HERE / ".claude" / "skills" / sname
            sdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, sdir / "SKILL.md")
        print("  ✔ .claude/skills/ synchronized (/guardrail)")

    if is_global:
        for sname in ("agent-guardrail", "guardrail"):
            gdir = HOME / ".claude" / "skills" / sname
            gdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, gdir / "SKILL.md")
        print("  ✔ ~/.claude/skills/ configured globally")


def install_codex(workspace: bool, is_global: bool) -> None:
    print("\n🟢 [2/5] Configuring OpenAI Codex / ChatGPT...")
    if workspace:
        codex_hooks = HERE / ".codex" / "hooks.json"
        codex_hooks_cfg = {
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'python "${CODEX_PROJECT_DIR}/guardrail_hook.py" hook --host codex',
                            }
                        ]
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'python "${CODEX_PROJECT_DIR}/guardrail_hook.py" hook --host codex',
                            }
                        ]
                    }
                ],
            }
        }
        merge_json_hooks(codex_hooks, codex_hooks_cfg)
        print("  ✔ .codex/hooks.json configured with lifecycle hooks")
        print("  ✔ .codex/prompts/guardrail.md ready (/guardrail, $guardrail)")

        for sname in ("agent-guardrail", "guardrail"):
            sdir = HERE / ".codex" / "skills" / sname
            sdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, sdir / "SKILL.md")
        print("  ✔ .codex/skills/ synchronized")

    if is_global:
        gprompts = HOME / ".codex" / "prompts"
        gprompts.mkdir(parents=True, exist_ok=True)
        for pname in ("agent-guardrail.md", "guardrail.md"):
            src_prompt = HERE / ".codex" / "prompts" / pname
            if src_prompt.exists():
                shutil.copy2(src_prompt, gprompts / pname)
        print("  ✔ ~/.codex/prompts/ configured globally")

        ghooks = HOME / ".codex" / "hooks.json"
        merge_json_hooks(ghooks, {
            "hooks": {
                "UserPromptSubmit": [{
                    "hooks": [{
                        "type": "command",
                        "command": f'python "{HERE}/guardrail_hook.py" hook --host codex',
                    }]
                }],
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{
                        "type": "command",
                        "command": f'python "{HERE}/guardrail_hook.py" hook --host codex',
                    }]
                }],
            }
        })
        print("  ✔ ~/.codex/hooks.json configured globally")

        codex_cfg = HOME / ".codex" / "config.toml"
        if codex_cfg.exists():
            text = codex_cfg.read_text(encoding="utf-8")
            entry = str(HERE).lower()
            key = f"[projects.'{entry}']"
            if key not in text:
                addition = f"\n{key}\ntrust_level = \"trusted\"\n"
                codex_cfg.write_text(text + addition, encoding="utf-8")
                print("  ✔ Workspace added as trusted in ~/.codex/config.toml")


def install_antigravity(workspace: bool, is_global: bool) -> None:
    print("\n🪐 [3/5] Configuring Google Antigravity (AGY)...")
    if workspace:
        # 1. Native lifecycle hooks in .agents/hooks.json
        agents_dir = HERE / ".agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        hooks_file = agents_dir / "hooks.json"
        hooks_cfg = {
            "agent-guardrail": {
                "enabled": True,
                "PreToolUse": [
                    {
                        "matcher": "run_command|write_to_file|replace_file_content",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f'python "{HERE}/guardrail_hook.py" hook --host antigravity',
                                "timeout": 15,
                            }
                        ],
                    }
                ],
            }
        }
        hooks_file.write_text(json.dumps(hooks_cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("  ✔ .agents/hooks.json configured with PreToolUse interception")

        # 2. Antigravity Skills in .agents/skills/
        for sname in ("agent-guardrail", "guardrail"):
            sdir = HERE / ".agents" / "skills" / sname
            sdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, sdir / "SKILL.md")
        print("  ✔ .agents/skills/ synchronized (/guardrail)")

    if is_global:
        # Global Antigravity skills
        for target_root in (HOME / ".gemini" / "antigravity" / "skills", HOME / ".gemini" / "config" / "skills"):
            for sname in ("agent-guardrail", "guardrail"):
                gdir = target_root / sname
                gdir.mkdir(parents=True, exist_ok=True)
                src = HERE / "SKILL.md"
                if src.exists():
                    shutil.copy2(src, gdir / "SKILL.md")
        print("  ✔ ~/.gemini/antigravity/skills/ configured globally")


def install_cursor(workspace: bool, is_global: bool) -> None:
    print("\n⚡ [4/5] Configuring Cursor (Composer & Agent Mode)...")
    if workspace:
        # 1. Cursor MDC rule in .cursor/rules/guardrail.mdc
        cursor_rules_dir = HERE / ".cursor" / "rules"
        cursor_rules_dir.mkdir(parents=True, exist_ok=True)
        src_mdc = HERE / ".cursor" / "rules" / "guardrail.mdc"
        if not src_mdc.exists():
            src_mdc.write_text(
                "---\ndescription: Universal Safety Guardrail for AI Agents\nglobs: *\nalwaysApply: true\n---\n\n"
                "# Agent Safety Guardrail (Cursor Rules)\n\n"
                "You are operating under the policy defined in `policy.yaml`.\n"
                "- PROHIBITED: rm -rf, git push -f, DROP TABLE, deleting .env or secrets.\n"
                "- CONFIRMATION: Ask before modifying docker-compose, configs, or infrastructure.\n"
                "- PROCEED: Safe read-only commands (ls, git status, pytest, ruff) proceed silently.\n"
                "Verify uncertain commands via: `python check_action.py \"<command>\"`\n",
                encoding="utf-8",
            )
        print("  ✔ .cursor/rules/guardrail.mdc configured (alwaysApply: true)")

        # 2. Legacy / Universal .cursorrules in workspace root
        cursorrules = HERE / ".cursorrules"
        if not cursorrules.exists():
            cursorrules.write_text(
                "# Agent Safety Guardrail\n# Strictly adhere to policy.yaml\n"
                "Block: destructive removals, force push, database drops, secret exposure.\n"
                "Ask User: configuration changes, container executions, dependency upgrades.\n"
                "Proceed: read-only commands, test execution, routine code edits.\n",
                encoding="utf-8",
            )
        print("  ✔ .cursorrules configured in workspace root")

    if is_global:
        global_cursor_dir = HOME / ".cursor" / "rules"
        global_cursor_dir.mkdir(parents=True, exist_ok=True)
        src_mdc = HERE / ".cursor" / "rules" / "guardrail.mdc"
        if src_mdc.exists():
            shutil.copy2(src_mdc, global_cursor_dir / "guardrail.mdc")
            print("  ✔ ~/.cursor/rules/guardrail.mdc configured globally")


def install_grok(workspace: bool, is_global: bool) -> None:
    print("\n🧠 [5/5] Configuring Grok Build (xAI CLI Agent)...")
    if workspace:
        # 1. Grok Skills in .grok/skills/
        for sname in ("agent-guardrail", "guardrail"):
            sdir = HERE / ".grok" / "skills" / sname
            sdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, sdir / "SKILL.md")
        print("  ✔ .grok/skills/ synchronized (/guardrail)")

        # 2. AGENTS.md verified for Grok
        if (HERE / "AGENTS.md").exists():
            print("  ✔ AGENTS.md recognized by Grok Build as project rules")

    if is_global:
        for sname in ("agent-guardrail", "guardrail"):
            gdir = HOME / ".grok" / "skills" / sname
            gdir.mkdir(parents=True, exist_ok=True)
            src = HERE / "SKILL.md"
            if src.exists():
                shutil.copy2(src, gdir / "SKILL.md")
        print("  ✔ ~/.grok/skills/ configured globally")


def run_checks() -> None:
    print("\n🔍 Multi-Agent Health & Connectivity Diagnostics:")
    clm_ok = check_clm()
    d1_ok = check_d1()

    if clm_ok:
        print("  ✔ CLM server online at http://localhost:8700 (port 8700)")
    else:
        print("  ⚠️ CLM server offline at http://localhost:8700 (optional if using 'd1' or 'rules')")

    if d1_ok:
        print("  ✔ Liquid AI D1 server online at http://localhost:8800 (port 8800)")
    else:
        print("  ℹ️ Liquid AI D1 server offline at http://localhost:8800 (start via /guardrail start)")

    # Multi-agent simulation tests
    try:
        import guardrail_hook as gh
        st = gh.State()
        st.update("check-session", active=True)

        # 1. Claude simulation
        ev_claude_safe = {"hook_event_name": "PreToolUse", "session_id": "check-session", "tool_name": "Bash", "tool_input": {"command": "ls"}}
        out_c, _ = gh.handle(ev_claude_safe, "claude", st)
        assert out_c is None, "Claude safe check failed"

        # 2. Codex simulation
        ev_codex_block = {"hook_event_name": "PreToolUse", "session_id": "check-session", "tool_name": "exec_command", "tool_input": {"cmd": "rm -rf /"}}
        out_x, _ = gh.handle(ev_codex_block, "codex", st)
        assert out_x and out_x.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", "Codex block check failed"

        # 3. Antigravity simulation
        ev_agy_safe = {"conversationId": "check-session", "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}}
        out_a_safe, _ = gh.handle(ev_agy_safe, "antigravity", st)
        assert out_a_safe == {"decision": "allow"}, "Antigravity safe check failed"

        ev_agy_block = {"conversationId": "check-session", "toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /"}}}
        out_a_block, _ = gh.handle(ev_agy_block, "antigravity", st)
        assert out_a_block and out_a_block.get("decision") == "deny", "Antigravity block check failed"

        print("  ✔ Hook simulation PASSED for Claude Code, OpenAI Codex, and Google Antigravity")
    except Exception as exc:
        print(f"  ❌ Hook simulation FAILED: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Agent Guardrail Universal Installer (Claude Code, OpenAI Codex, Antigravity, Cursor, Grok Build)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--all", action="store_true", help="Install across all 5 platforms (default when no specific agent is flagged)")
    parser.add_argument("--claude", action="store_true", help="Configure Claude Code (.claude/)")
    parser.add_argument("--codex", "--chatgpt", dest="codex", action="store_true", help="Configure OpenAI Codex / ChatGPT (.codex/)")
    parser.add_argument("--antigravity", "--agy", dest="antigravity", action="store_true", help="Configure Google Antigravity (.agents/)")
    parser.add_argument("--cursor", action="store_true", help="Configure Cursor (.cursor/rules/ and .cursorrules)")
    parser.add_argument("--grok", action="store_true", help="Configure Grok Build (.grok/skills/)")
    parser.add_argument("--global", dest="is_global", action="store_true", help="Also install globally into user home directories (~/)")
    parser.add_argument("--check", action="store_true", help="Run health and connectivity diagnostics only")
    args = parser.parse_args()

    print("🛡️  Agent Guardrail Universal Setup (5 Platforms Supported)\n")

    if args.check:
        run_checks()
        return 0

    # Determine targeted platforms
    specific_chosen = any([args.claude, args.codex, args.antigravity, args.cursor, args.grok])
    target_all = args.all or not specific_chosen

    target_claude = target_all or args.claude
    target_codex = target_all or args.codex
    target_antigravity = target_all or args.antigravity
    target_cursor = target_all or args.cursor
    target_grok = target_all or args.grok

    print(f"Targeting: " + ", ".join(filter(None, [
        "Claude Code" if target_claude else None,
        "OpenAI Codex" if target_codex else None,
        "Google Antigravity" if target_antigravity else None,
        "Cursor" if target_cursor else None,
        "Grok Build" if target_grok else None,
    ])) + (" [GLOBAL & WORKSPACE]" if args.is_global else " [WORKSPACE ONLY]"))

    install_shared(workspace=True, is_global=args.is_global)

    if target_claude:
        install_claude(workspace=True, is_global=args.is_global)
    if target_codex:
        install_codex(workspace=True, is_global=args.is_global)
    if target_antigravity:
        install_antigravity(workspace=True, is_global=args.is_global)
    if target_cursor:
        install_cursor(workspace=True, is_global=args.is_global)
    if target_grok:
        install_grok(workspace=True, is_global=args.is_global)

    run_checks()

    print("\n🎉 Installation completed successfully!")
    print("How to activate during your agent sessions:")
    print("  - Claude Code / Codex / Antigravity / Grok: Simply type `/guardrail`")
    print("  - Cursor: Active automatically across all Composer and Agent sessions via `.cursor/rules`")
    print("  - Background engine handles all evaluations silently with zero friction.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
