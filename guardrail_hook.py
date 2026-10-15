#!/usr/bin/env python3
"""
Lifecycle guardrail hook for Claude Code and OpenAI Codex / ChatGPT.

Automatically intercepts prompts and tool calls in the background:
    guardrail_hook.py hook --host claude|codex
    guardrail_hook.py on|off|status [--session ID]
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GUARDRAIL_HOME = Path(os.environ.get("GUARDRAIL_HOME", Path.home() / ".guardrail"))
STATE_PATH = GUARDRAIL_HOME / "state.json"
CONFIG_PATH = GUARDRAIL_HOME / "config.json"
LOG_PATH = GUARDRAIL_HOME / "guardrail.log"

BREAKER_SECS = 30
CONFIRM_WINDOW_SECS = 600
SESSION_TTL_SECS = 7 * 24 * 3600

ICON = "\U0001F6E1\uFE0F"


# --- Config & State ---


def load_config() -> None:
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    for key, value in (cfg.get("env") or {}).items():
        if value is not None:
            os.environ.setdefault(str(key), str(value))


def _load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    sessions = state.get("sessions", {})
    state["sessions"] = {k: v for k, v in sessions.items() if now - v.get("ts", now) < SESSION_TTL_SECS}
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


class State:
    def __init__(self, path: Path = STATE_PATH):
        self.path = path
        self.data = _load_state(path)
        self.dirty = False

    def session(self, sid: str) -> dict:
        sessions = self.data.setdefault("sessions", {})
        return sessions.setdefault(sid or "_default", {})

    def update(self, sid: str, **fields) -> None:
        s = self.session(sid)
        s.update(fields)
        s["ts"] = time.time()
        self.dirty = True

    def breaker_open(self) -> bool:
        return time.time() - float(self.data.get("backend_failed_at", 0)) < BREAKER_SECS

    def trip_breaker(self) -> None:
        self.data["backend_failed_at"] = time.time()
        self.dirty = True

    def save(self) -> None:
        if self.dirty:
            _save_state(self.path, self.data)


def is_active(state: State, sid: str, host: str) -> bool:
    if os.environ.get("GUARDRAIL_AUTO_ACTIVATE", "").lower() in ("1", "true", "yes", "on"):
        return True
    s = state.session(sid)
    if "active" in s:
        return bool(s["active"])
    def_s = state.session("_default")
    if "active" in def_s:
        return bool(def_s["active"])
    if host in ("antigravity", "agy", "gemini"):
        return True
    return False


def log(entry: dict) -> None:
    try:
        GUARDRAIL_HOME.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **entry}
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


# --- Commands & Prompts ---

_EXPLICIT_CMD_RE = re.compile(
    r"^\s*(?:\[\[(?:agent[-_])?guardrail:(?P<marker>on|off|status)\]\]|[/$](?:prompts:)?(?:agent[-_])?guardrail(?:\b|$))\s*(?P<arg>\S+)?",
    re.IGNORECASE,
)
_PLAIN_CMD_RE = re.compile(
    r"^\s*(?:agent[-_])?guardrail(?:\s+(?P<arg>\S+))?\s*$",
    re.IGNORECASE,
)
_ARG_MAP = {
    "on": "on", "enable": "on", "": "on",
    "start": "start",
    "off": "off", "disable": "off",
    "stop": "stop",
    "status": "status", "info": "status",
}
_CONFIRM_RE = re.compile(
    r"\b(?:yes|y|ok|okay|confirm|confirmed|approve|approved|proceed|go|continue|done)\b",
    re.IGNORECASE,
)
_NEGATION_RE = re.compile(
    r"\b(?:no|cancel|abort|stop|reject|deny)\b",
    re.IGNORECASE,
)


def is_confirmation(prompt: str) -> bool:
    text = (prompt or "").strip()
    if not text:
        return False
    if _NEGATION_RE.search(text) and not re.search(r"\b(?:ok|yes|confirm|proceed|continue)\b", text, re.IGNORECASE):
        return False
    return bool(_CONFIRM_RE.search(text))


def parse_command(prompt: str) -> str | None:
    text = (prompt or "").strip()
    if not text:
        return None
    m = _EXPLICIT_CMD_RE.match(text)
    if m:
        marker = (m.group("marker") or "").lower()
        if marker:
            return _ARG_MAP.get(marker, "on")
        arg = (m.group("arg") or "").lower()
        return _ARG_MAP.get(arg, "on")
    m2 = _PLAIN_CMD_RE.match(text)
    if m2:
        arg = (m2.group("arg") or "").lower()
        return _ARG_MAP.get(arg, "on")
    return None


def status_text(active: bool) -> str:
    backend = os.environ.get("GUARDRAIL_BACKEND", "clm")
    if active:
        return f"{ICON} Agent Guardrail ACTIVE (backend: {backend}). Every shell command, file modification, and tool execution is evaluated before running."
    return f"{ICON} Agent Guardrail DISABLED for this session."


# --- Tool Inspection ---

SKIP_TOOLS = {
    # Claude Code
    "read", "glob", "grep", "ls", "websearch", "todowrite", "todoread", "askuserquestion",
    "exitplanmode", "enterplanmode", "skill", "agent", "task", "notebookread", "toolsearch",
    "subagenthandback", "bashoutput", "killshell", "monitor",
    # Codex
    "update_plan", "view_image", "web_search", "list_mcp_resources", "read_mcp_resource",
    "write_stdin", "spawn_agent", "wait",
}
SHELL_TOOLS = {
    "bash", "powershell", "shell", "exec_command", "local_shell", "unified_exec",
    "terminal", "execute_command", "run_command", "bash_20241022",
}
EDIT_TOOLS = {"write", "edit", "multiedit", "notebookedit", "fileedit", "writefile", "replace_file_content", "write_to_file"}
DELETE_TOOLS = {"filedelete", "deletefile", "delete_file"}

_SAFE_CMDS = {
    "ls", "dir", "pwd", "cd", "cat", "type", "head", "tail", "less", "more", "wc", "grep", "rg",
    "egrep", "find", "fd", "tree", "which", "where", "whoami", "date", "echo", "printf", "file",
    "stat", "du", "df", "sort", "uniq", "diff", "cut", "awk", "jq",
    "get-childitem", "gci", "get-content", "gc", "select-string", "sls", "get-location", "gl",
    "test-path", "get-item", "gi", "resolve-path", "measure-object", "write-output", "write-host",
    "set-location", "sl",
    "pytest", "tsc", "eslint", "ruff", "mypy", "flake8", "black", "prettier",
}
_SAFE_PREFIXES = (
    "git status", "git diff", "git log", "git show", "git branch --show-current", "git branch -a",
    "git branch --list", "git remote -v", "git rev-parse", "git ls-files", "git blame", "git fetch --dry-run",
    "python -m pytest", "python3 -m pytest", "python -m unittest", "python3 -m unittest", "py -m pytest",
    "python --version", "python3 --version", "node --version", "npm --version", "npm test", "npm run test",
    "npm run lint", "npm run build", "npm ls", "pnpm test", "yarn test", "cargo test", "cargo check",
    "cargo build", "go test", "go vet", "go build", "dotnet test", "dotnet build", "pip list", "pip show",
    "pip freeze", "npx tsc", "make test",
)


def is_safe_readonly(command: str) -> bool:
    cmd = command.strip()
    if not cmd or re.search(r"(?<![0-9&])>|\$\(|`|<\(|>\(|<<<|<<", cmd):
        return False
    # Reject commands containing encoded payloads
    if re.search(r"(?:-|/)(?:encodedcommand|enc|ec|e)\b|\b(?:base64\s+-(?:d|-decode)|certutil\s+-decode)\b", cmd, re.IGNORECASE):
        return False
    # Reject inline script execution wrappers
    if re.search(r"\b(?:python\d?|node|perl|ruby|php)\b\s+-(?:c|e|r|-eval)\b", cmd, re.IGNORECASE):
        return False
    # Reject execution sinks
    if re.search(r"\b(?:eval|exec|xargs)\b", cmd, re.IGNORECASE):
        return False
    # Reject environment variable execution hijacking
    if re.search(r"(?:^|[\s;&|])(?:LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_OPTIONS|BASH_ENV|PERL5OPT|RUBYOPT|DYLD_INSERT_LIBRARIES)\s*=", cmd, re.IGNORECASE):
        return False
    # Reject reverse shells & network pseudo-devices
    if re.search(r"/dev/(?:tcp|udp)/\S+|\b(?:nc|ncat|netcat)\b.*-(?:e|c|--exec)\b|\bsocat\b", cmd, re.IGNORECASE):
        return False
    for seg in re.split(r"&&|\|\||;|\||\n", cmd):
        seg = seg.strip()
        if not seg:
            continue
        low = " ".join(seg.lower().split())
        if any(low == p or low.startswith(p + " ") for p in _SAFE_PREFIXES):
            # Even for safe prefixes (like git log/diff/show), reject argument injections
            if re.search(r"(?:--output|-c\s+core|--exec-path)\b", low):
                return False
            continue
        try:
            first = shlex.split(seg, posix=True)[0].lower()
        except (ValueError, IndexError):
            return False
        first = first.replace("\\", "/").rsplit("/", 1)[-1]
        if first.endswith(".exe"):
            first = first[:-4]
        if first not in _SAFE_CMDS:
            return False
        # GTFOBins & argument injection checks on allowed commands
        if first == "find" and re.search(r"-(?:delete|exec|execdir|ok|okdir)\b", low):
            return False
        if first in ("rg", "ripgrep") and re.search(r"--(?:pre|pre-glob|rure)\b", low):
            return False
        if first in ("fd", "fdfind") and re.search(r"-(?:x|X|-exec|-exec-batch)\b", low):
            return False
        if first in ("awk", "gawk", "mawk", "nawk") and re.search(r"(?:\bsystem\s*\(|\bgetline\b|-f\b|-e\b|>)", low):
            return False
    return True


def _outside(path: str, cwd: str) -> bool:
    if not path or not cwd:
        return False
    try:
        p = os.path.normcase(os.path.abspath(path))
        c = os.path.normcase(os.path.abspath(cwd))
        return os.path.commonpath([p, c]) != c
    except ValueError:
        return True


def _patch_actions(patch: str) -> list[str]:
    ops = {"add": "create file", "update": "modify file", "delete": "delete file"}
    out = []
    for m in re.finditer(r"^\*\*\* (Add|Update|Delete) File: (.+)$", patch or "", re.MULTILINE):
        out.append(f"{ops[m.group(1).lower()]} {m.group(2).strip()}")
    for m in re.finditer(r"^\*\*\* Move to: (.+)$", patch or "", re.MULTILINE):
        out.append(f"move file to {m.group(1).strip()}")
    return out


_GUARDRAIL_CONTROL_FILES = (
    "policy.yaml", "policy.yml", "check_action.py", "guardrail_hook.py",
    "daemon_manager.py", "install.py", ".guardrail", ".claude/settings.json",
    ".codex/hooks.json", ".agents/hooks.json", ".cursorrules",
)


def _is_guardrail_file(path: str) -> bool:
    p_canon = path.replace("\\", "/").lower()
    return any(gf in p_canon or p_canon.endswith(gf.lstrip("/")) for gf in _GUARDRAIL_CONTROL_FILES)


def describe_tool(event: dict) -> tuple[str | None, bool, list[str]]:
    if "toolCall" in event and isinstance(event["toolCall"], dict):
        tc = event["toolCall"]
        name = str(tc.get("name") or "")
        inp = tc.get("args") or {}
    else:
        name = str(event.get("tool_name") or "")
        inp = event.get("tool_input")
    low = name.lower()
    inp = inp if isinstance(inp, dict) else {"value": inp}

    if low in SKIP_TOOLS:
        return None, False, []

    if low in SHELL_TOOLS:
        command = inp.get("command") or inp.get("CommandLine") or inp.get("cmd") or ""
        if isinstance(command, list):
            command = " ".join(map(str, command))
        command = str(command)
        desc = command
        if inp.get("description"):
            desc = f"{command}\n(description: {inp['description']})"
        return desc, is_safe_readonly(command), []

    if low == "apply_patch":
        patch = str(inp.get("command") or inp.get("patch") or inp.get("input") or "")
        actions = _patch_actions(patch)
        paths = [a.split(" ", 3)[-1] for a in actions]
        for p in paths:
            if _is_guardrail_file(p):
                return f"tamper guardrail control plane: apply patch to {p}", False, paths
        desc = ("; ".join(actions) or "apply patch to files")
        if patch:
            desc += f"\n[patch-content]:\n{patch[:2000]}"
        return desc, False, paths

    if low in DELETE_TOOLS:
        path = str(inp.get("file_path") or inp.get("path") or inp.get("TargetFile") or "")
        if _is_guardrail_file(path):
            return f"tamper guardrail control plane: delete file {path}", False, [path]
        return f"delete file {path}", False, [path]

    if low in EDIT_TOOLS:
        path = str(inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or inp.get("TargetFile") or "")
        verb = "write file" if low in ("write", "writefile", "write_to_file") else "modify file"
        if _is_guardrail_file(path):
            return f"tamper guardrail control plane: {verb} {path}", False, [path]
        content = (
            inp.get("CodeContent")
            or inp.get("content")
            or inp.get("ReplacementContent")
            or inp.get("new_string")
            or inp.get("new_str")
            or inp.get("text")
            or ""
        )
        if isinstance(content, str) and content.strip():
            content_snippet = content[:2000].replace("\r", "")
            return f"{verb} {path}\n[content]:\n{content_snippet}", False, [path]
        return f"{verb} {path}", False, [path]

    if low == "webfetch":
        return None, False, []

    args = json.dumps(inp, ensure_ascii=False)[:800]
    return f"execute tool {name} with arguments {args}", False, []


# --- Output Formatting ---


def _reason(decision) -> str:
    parts = []
    if decision.rules.matched:
        parts.append("rules: " + ", ".join(m.split(":", 1)[1] for m in decision.rules.matched))
    if decision.model is not None:
        parts.append(f"model: {decision.model.decision}")
    if decision.error:
        parts.append("backend unavailable")
    return "; ".join(parts) or decision.decision


def pre_tool_output(host: str, decision: str, reason: str, context: str | None = None) -> dict:
    if host in ("antigravity", "agy", "gemini"):
        d = "allow" if decision in ("allow", "proceed") else ("deny" if decision in ("deny", "block") else "ask")
        res = {"decision": d}
        if reason:
            res["reason"] = reason
        return res
    hso = {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}
    if context:
        hso["additionalContext"] = context
    return {"hookSpecificOutput": hso}


# --- Evaluation Engine ---


def evaluate(description: str, state: State):
    import check_action as ca

    if state.breaker_open():
        rules = ca.evaluate_rules(description)
        return ca.Decision(ca.fallback_decision(description), os.environ.get("GUARDRAIL_BACKEND", "clm"),
                           rules, error="backend cooling down after recent error")
    result = ca.decide(description)
    if result.error and result.rules.decision != "block":
        state.trip_breaker()
    return result


# --- Event Handlers ---


def on_prompt_submit(event: dict, host: str, state: State):
    sid = str(event.get("session_id") or "")
    prompt = str(event.get("prompt") or "")
    turn = event.get("turn_id")
    cmd = parse_command(prompt)

    if cmd is not None:
        daemon_msg = ""
        if cmd in ("on", "start"):
            if cmd == "start":
                try:
                    import daemon_manager
                    _, daemon_msg = daemon_manager.start_daemon()
                except Exception as exc:
                    daemon_msg = f"Daemon starter note: {exc}"
            state.update(sid, active=True, pending=None, approved_turn=None)
            state.update("_default", active=True, pending=None, approved_turn=None)
        elif cmd in ("off", "stop"):
            if cmd == "stop":
                try:
                    import daemon_manager
                    _, daemon_msg = daemon_manager.stop_daemon()
                except Exception as exc:
                    daemon_msg = f"Daemon stop note: {exc}"
            state.update(sid, active=False, pending=None, approved_turn=None)
            state.update("_default", active=False, pending=None, approved_turn=None)

        active = is_active(state, sid, host) if cmd == "status" else (cmd in ("on", "start"))
        log({"host": host, "event": "command", "session": sid, "cmd": cmd, "active": active})

        status_rep = ""
        if cmd == "status":
            try:
                import daemon_manager
                status_rep = "\n\n" + daemon_manager.format_status_report()
            except Exception:
                pass

        combined_msg = f"{daemon_msg}\n\n" if daemon_msg else ""

        if host == "claude":
            if cmd in ("off", "stop"):
                return {
                    "decision": "block",
                    "continue": False,
                    "stopReason": f"{combined_msg}{status_text(False)}",
                    "reason": f"{combined_msg}{status_text(False)}",
                }, 0
            if cmd == "status":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": f"{status_text(active)}{status_rep}",
                    }
                }, 0
            # cmd in ("on", "start"): inject context
            return {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": (
                        f"{combined_msg}{status_text(True)}\nInform the user that the guardrail is active. "
                        "Do not run manual Python checking scripts before commands: "
                        "proceed normally and checks will run automatically in the background via hooks."
                    ),
                }
            }, 0

        # Codex / other hosts
        if cmd == "status":
            return {
                "decision": "block",
                "continue": False,
                "stopReason": f"{status_text(active)}{status_rep}",
                "reason": f"{status_text(active)}{status_rep}",
            }, 0
        if cmd in ("off", "stop"):
            return {
                "decision": "block",
                "continue": False,
                "stopReason": f"{combined_msg}{status_text(False)}",
                "reason": f"{combined_msg}{status_text(False)}",
            }, 0
        return {
            "decision": "block",
            "continue": False,
            "stopReason": f"{combined_msg}{status_text(True)}",
            "reason": (
                f"{combined_msg}{status_text(True)}\nDo not run manual Python scripts to verify actions: "
                "the guardrail is active in the background via hooks."
            ),
        }, 0

    if not is_active(state, sid, host):
        return None, 0

    s = state.session(sid)
    if host == "codex" and s.get("pending") and is_confirmation(prompt):
        state.update(sid, approved_turn=turn or f"t{time.time():.0f}", approved_at=time.time(), pending=None)
        log({"host": host, "event": "confirm", "session": sid})
        return {"hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": (
                f"{ICON} GUARDRAIL: user confirmed. You may execute the requested action this turn "
                "('block' actions remain strictly prohibited)."
            ),
        }}, 0

    result = evaluate(prompt, state)
    log({"host": host, "event": "prompt", "session": sid, "text": prompt[:300],
         "decision": result.decision, "why": result.explain()})

    if result.decision == "block":
        msg = (
            f"{ICON} Guardrail: request BLOCKED ({_reason(result)}). "
            "If intentional, execute manually or disable via /guardrail off."
        )
        return {
            "decision": "block",
            "continue": False,
            "stopReason": msg,
            "reason": msg,
        }, 0

    if result.decision == "ask_user":
        if host == "codex":
            state.update(sid, pending={"text": prompt[:300], "at": time.time()})
        return {
            "systemMessage": f"{ICON} Guardrail: confirmation required ({_reason(result)})",
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"{ICON} GUARDRAIL (ask_user): this request carries risk ({_reason(result)}). "
                    "BEFORE executing any changes, explain the exact actions to the user and request explicit confirmation. "
                    "Do not proceed until the user confirms."
                ),
            },
        }, 0

    return None, 0


def on_prompt_expansion(event: dict, host: str, state: State):
    cmd_name = str(event.get("command_name") or "").split(":")[-1].lower()
    if cmd_name != "guardrail":
        return None, 0
    sid = str(event.get("session_id") or "")
    arg = str(event.get("command_args") or "").strip().lower().split(" ")[0]
    cmd = _ARG_MAP.get(arg, "on")
    if cmd in ("on", "off"):
        state.update(sid, active=(cmd == "on"), pending=None, approved_turn=None)
        state.update("_default", active=(cmd == "on"), pending=None, approved_turn=None)
    active = is_active(state, sid, host) if cmd == "status" else (cmd == "on")
    log({"host": host, "event": "command", "session": sid, "cmd": cmd, "active": active})
    if cmd in ("off", "status"):
        return {"decision": "block", "reason": status_text(active)}, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptExpansion",
            "additionalContext": (
                f"{status_text(True)}\nInform the user that the guardrail is active. "
                "Do not run manual Python scripts: the guardrail operates in the background via hooks."
            ),
        }
    }, 0


def on_pre_tool(event: dict, host: str, state: State):
    sid = str(event.get("session_id") or event.get("conversationId") or "_default")
    if not is_active(state, sid, host):
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "allow"}, 0
        return None, 0

    desc, safe_shell, paths = describe_tool(event)
    if desc is None:
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "allow"}, 0
        return None, 0

    import check_action as ca

    rules = ca.evaluate_rules(desc)
    cwd = str(event.get("cwd") or (event.get("workspacePaths", [""])[0] if event.get("workspacePaths") else ""))
    outside = [p for p in paths if _outside(p, cwd)]

    tool_ident = event.get("tool_name") or (event.get("toolCall", {}).get("name") if isinstance(event.get("toolCall"), dict) else "")

    if rules.decision == "proceed" and safe_shell:
        log({"host": host, "event": "tool", "session": sid, "tool": tool_ident,
             "text": desc[:300], "decision": "proceed", "why": "safe read-only command"})
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "allow"}, 0
        return None, 0

    result = evaluate(desc, state)
    final = result.decision
    reason = _reason(result)
    if outside and final == "proceed":
        final, reason = "ask_user", "file outside project directory: " + ", ".join(outside)

    log({"host": host, "event": "tool", "session": sid, "tool": tool_ident,
         "text": desc[:300], "decision": final, "why": result.explain()})

    short = desc.splitlines()[0][:160]
    if final == "block":
        return pre_tool_output(host, "deny",
                               f"{ICON} GUARDRAIL: action BLOCKED ({reason}): {short}. "
                               "Do not retry or attempt bypasses: explain why it was blocked."), 0

    if final == "ask_user":
        if host == "claude":
            return pre_tool_output(host, "ask", f"{ICON} Guardrail: confirmation required ({reason}): {short}"), 0
        if host in ("antigravity", "agy", "gemini"):
            return pre_tool_output(host, "ask", f"{ICON} Guardrail: confirmation required ({reason}): {short}"), 0
        s = state.session(sid)
        turn = event.get("turn_id")
        approved = s.get("approved_turn")
        if approved and ((turn and approved == turn) or
                         (not turn and time.time() - float(s.get("approved_at", 0)) < CONFIRM_WINDOW_SECS)):
            return None, 0
        state.update(sid, pending={"text": short, "at": time.time()})
        return pre_tool_output(host, "deny",
                               f"{ICON} GUARDRAIL (ask_user): action paused, user confirmation required ({reason}): {short}. "
                               "Ask the user if they wish to proceed explaining the risk. If they confirm, retry the action."), 0

    if host in ("antigravity", "agy", "gemini"):
        return {"decision": "allow"}, 0
    return None, 0


HANDLERS = {
    "UserPromptSubmit": on_prompt_submit,
    "UserPromptExpansion": on_prompt_expansion,
    "PreToolUse": on_pre_tool,
}


def handle(event: dict, host: str, state: State | None = None):
    state = state or State()
    event_name = str(event.get("hook_event_name") or "")
    if not event_name:
        if "toolCall" in event or "tool_name" in event:
            event_name = "PreToolUse"
        elif "prompt" in event or "userPrompt" in event:
            event_name = "UserPromptSubmit"
    handler = HANDLERS.get(event_name)
    if handler is None:
        if host in ("antigravity", "agy", "gemini") and "toolCall" in event:
            return {"decision": "allow"}, 0
        return None, 0
    try:
        out = handler(event, host, state)
    finally:
        state.save()
    return out


# --- CLI ---


def _write_stdout(obj: dict) -> None:
    sys.stdout.buffer.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))
    sys.stdout.buffer.flush()


def main(argv: list[str]) -> int:
    load_config()
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2

    if argv[0] == "hook":
        host = "codex"
        if "--host" in argv:
            host = argv[argv.index("--host") + 1].lower()
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        try:
            event = json.loads(raw) if raw.strip() else {}
        except ValueError:
            return 0
        try:
            out, code = handle(event, host)
        except Exception as exc:  # noqa: BLE001
            log({"host": host, "event": "error", "error": f"{type(exc).__name__}: {exc}"})
            if event.get("hook_event_name") == "PreToolUse" or "toolCall" in event:
                d = "ask" if host in ("claude", "antigravity", "agy", "gemini") else "deny"
                _write_stdout(pre_tool_output(host, d, f"{ICON} Guardrail: internal error ({exc}), confirmation required"))
            return 0
        if out is not None:
            _write_stdout(out)
        return code

    if argv[0] in ("on", "off", "status"):
        sid = argv[argv.index("--session") + 1] if "--session" in argv else "_default"
        st = State()
        if argv[0] != "status":
            st.update(sid, active=(argv[0] == "on"))
            st.save()
        print(status_text(is_active(st, sid, "codex")))
        return 0

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
