#!/usr/bin/env python3
"""
Lifecycle guardrail hook for Claude Code and OpenAI Codex / ChatGPT.

Automatically intercepts prompts and tool calls in the background:
    guardrail_hook.py hook --host claude|codex
    guardrail_hook.py on|off|status|reload [--session ID] [--policy FILE]
"""

from __future__ import annotations

import hashlib
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
ACTION_HISTORY_TTL_SECS = 1800
MAX_ACTION_HISTORY = 20
_GENESIS_HASH = "0" * 64

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

    def record_action(self, sid: str, summary: str, capabilities: list[str]) -> None:
        """Record a bounded, time-expiring action entry in session memory for trajectory analysis."""
        import check_action as ca
        mem_cfg = ca.get_memory_config()
        ttl = float(mem_cfg.get("action_history_ttl_secs", ACTION_HISTORY_TTL_SECS))
        max_hist = int(mem_cfg.get("max_action_history", MAX_ACTION_HISTORY))
        now = time.time()
        s = self.session(sid)
        history: list[dict] = [
            h for h in (s.get("action_history") or [])
            if isinstance(h, dict) and now - float(h.get("ts", 0)) < ttl
        ]
        history.append({
            "summary": summary[:160],
            "capabilities": list(capabilities),
            "ts": now,
        })
        s["action_history"] = history[-max_hist:]
        s["ts"] = now
        self.dirty = True

    def recent_capabilities(self, sid: str) -> list[str]:
        """Return deduplicated capabilities executed within the active session history window."""
        import check_action as ca
        mem_cfg = ca.get_memory_config()
        ttl = float(mem_cfg.get("action_history_ttl_secs", ACTION_HISTORY_TTL_SECS))
        now = time.time()
        s = self.session(sid)
        caps: list[str] = []
        for h in (s.get("action_history") or []):
            if isinstance(h, dict) and now - float(h.get("ts", 0)) < ttl:
                for c in (h.get("capabilities") or []):
                    if c not in caps:
                        caps.append(c)
        return caps

    def recent_actions(self, sid: str) -> list[str]:
        import check_action as ca
        mem_cfg = ca.get_memory_config()
        ttl = float(mem_cfg.get("action_history_ttl_secs", ACTION_HISTORY_TTL_SECS))
        now = time.time()
        s = self.session(sid)
        return [
            str(h.get("summary", ""))
            for h in (s.get("action_history") or [])
            if isinstance(h, dict) and now - float(h.get("ts", 0)) < ttl
        ]

    def breaker_open(self) -> bool:
        return time.time() - float(self.data.get("backend_failed_at", 0)) < BREAKER_SECS

    def trip_breaker(self) -> None:
        self.data["backend_failed_at"] = time.time()
        self.dirty = True

    def save(self) -> None:
        if self.dirty:
            _save_state(self.path, self.data)


def compute_action_fingerprint(description: str, tool_name: str = "", cwd: str = "") -> str:
    """Compute a deterministic SHA-256 scope fingerprint binding command, tool, and working directory."""
    first_line = " ".join((description or "").strip().splitlines()[0].lower().split()) if (description or "").strip() else ""
    norm_tool = (tool_name or "").strip().lower()
    norm_cwd = ""
    if cwd:
        try:
            norm_cwd = os.path.normcase(os.path.abspath(cwd)).replace("\\", "/")
        except Exception:
            norm_cwd = cwd.strip().lower().replace("\\", "/")
    payload = f"{norm_tool}|{norm_cwd}|{first_line}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def _compute_entry_hash(record_without_hash: dict) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def log(entry: dict, log_path: Path | None = None) -> dict | None:
    """Append a tamper-evident, SHA-256 hash-chained JSONL entry to the audit log."""
    import check_action as ca
    audit_cfg = ca.get_audit_config()
    if not audit_cfg.get("enabled", True):
        return None
    custom_log = audit_cfg.get("log_file")
    target = log_path or (Path(custom_log) if custom_log else LOG_PATH)
    use_chaining = audit_cfg.get("hash_chaining", True)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        prev_seq = 0
        prev_hash = _GENESIS_HASH
        if target.is_file() and use_chaining:
            try:
                with target.open("r", encoding="utf-8", errors="replace") as rfh:
                    last_line = ""
                    for line in rfh:
                        if line.strip():
                            last_line = line.strip()
                    if last_line:
                        last_obj = json.loads(last_line)
                        prev_seq = int(last_obj.get("seq", 0))
                        prev_hash = str(last_obj.get("entry_hash") or _GENESIS_HASH)
            except Exception:
                pass

        record = {
            "seq": prev_seq + 1,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "prev_hash": prev_hash if use_chaining else "",
            **entry,
        }
        if use_chaining:
            record.pop("entry_hash", None)
            record["entry_hash"] = _compute_entry_hash(record)
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
    except OSError:
        return None


def verify_audit_log(log_path: Path | None = None) -> tuple[bool, str, int]:
    """
    Verify the cryptographic hash chain and sequence integrity of the append-only audit log.
    Returns (is_valid, message, entries_checked_or_failed_line).
    """
    target = log_path or LOG_PATH
    if not target.is_file():
        return True, "Audit log is empty (no entries yet)", 0

    expected_seq = 1
    expected_prev_hash = _GENESIS_HASH
    count = 0

    try:
        with target.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError as exc:
                    return False, f"Malformed JSON at line {line_no}: {exc}", line_no

                seq = obj.get("seq")
                prev_hash = obj.get("prev_hash")
                claimed_hash = obj.get("entry_hash")

                if seq != expected_seq:
                    return False, f"Sequence gap/reorder at line {line_no}: expected seq={expected_seq}, got seq={seq}", line_no
                if prev_hash != expected_prev_hash:
                    return False, f"Broken hash chain at line {line_no} (seq={seq}): prev_hash mismatch", line_no

                check_copy = dict(obj)
                check_copy.pop("entry_hash", None)
                actual_hash = _compute_entry_hash(check_copy)
                if claimed_hash != actual_hash:
                    return False, f"Entry payload tampered at line {line_no} (seq={seq}): entry_hash mismatch", line_no

                expected_seq += 1
                expected_prev_hash = actual_hash
                count += 1
    except OSError as exc:
        return False, f"Failed to read audit log: {exc}", 0

    return True, f"Audit log verified ({count} entries intact)", count


# --- Commands & Prompts ---

_EXPLICIT_CMD_RE = re.compile(
    r"^\s*(?:\[\[(?:agent[-_])?guardrail:(?P<marker>on|off|status|reload|why|doctor|check)\]\]|[/$](?:prompts:)?(?:agent[-_])?guardrail(?:\b|$))\s*(?P<arg>\S+)?(?:\s+(?P<rest>.*))?$",
    re.IGNORECASE | re.DOTALL,
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
    "reload": "reload", "r": "reload",
    "why": "why",
    "doctor": "doctor", "health": "doctor",
    "check": "check", "test": "check",
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


def parse_command_with_arg(prompt: str) -> tuple[str | None, str]:
    text = (prompt or "").strip()
    if not text:
        return None, ""
    m = _EXPLICIT_CMD_RE.match(text)
    if m:
        marker = (m.group("marker") or "").lower()
        arg = (m.group("arg") or "").strip()
        rest = (m.group("rest") or "").strip()
        if marker:
            cmd = _ARG_MAP.get(marker, "on")
            payload = f"{arg} {rest}".strip() if arg else rest
            return cmd, payload
        cmd = _ARG_MAP.get(arg.lower(), "on")
        return cmd, rest
    m2 = _PLAIN_CMD_RE.match(text)
    if m2:
        arg = (m2.group("arg") or "").lower()
        return _ARG_MAP.get(arg, "on"), ""
    return None, ""


def parse_command(prompt: str) -> str | None:
    cmd, _ = parse_command_with_arg(prompt)
    return cmd


def status_text(active: bool) -> str:
    backend = os.environ.get("GUARDRAIL_BACKEND")
    if not backend:
        try:
            import check_action as ca
            if not ca._POLICY_LOADED:
                ca.load_policy()
            backend = str(ca._POLICY_SETTINGS.get("backend", "rules"))
        except Exception:
            backend = "rules"
    if active:
        return f"{ICON} Agent Guardrail ACTIVE (backend: {backend}). Every shell command, file modification, and tool execution is evaluated before running."
    return f"{ICON} Agent Guardrail DISABLED for this session."


def format_check_report(action_text: str) -> str:
    """Evaluate a command or action in dry-run mode without executing it."""
    import check_action as ca
    text = (action_text or "").strip()
    if not text:
        return f"{ICON} Usage: `/guardrail check <command>` (e.g., `/guardrail check rm -rf build/`)"
    ctx = ca.ExecutionContext(cwd=os.getcwd())
    res = ca.decide(text, context=ctx)
    matched = ", ".join(res.rules.matched) if res.rules.matched else "none"
    caps = ", ".join(res.capabilities) if res.capabilities else "none"
    lines = [
        f"{ICON} Agent Guardrail Dry-Run Check:",
        f"  • Command / Intent: `{text}`",
        f"  • Verdict: **{res.decision.upper()}** (risk score: `{res.risk_score:.2f}`, backend: `{res.backend}`)",
        f"  • Matched Rules: {matched}",
        f"  • Capabilities: {caps}",
    ]
    if res.dry_run_preview:
        lines.append(f"  • Dry-Run Preview: {res.dry_run_preview}")
    return "\n".join(lines)


def format_why_report(log_path: Path | None = None) -> str:
    """Inspect the most recent blocked or confirmation-required entry in the audit log."""
    target = log_path or LOG_PATH
    if not target.is_file():
        return f"{ICON} No audit log found at {target} (no actions intercepted yet)."
    last_entry = None
    try:
        with target.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("decision") in ("block", "ask_user") or obj.get("event") in (
                    "self_tamper", "chained_exfil", "approval_expired", "approval_mismatch"
                ):
                    last_entry = obj
    except OSError as exc:
        return f"{ICON} Could not read audit log: {exc}"

    if not last_entry:
        return f"{ICON} No blocked or confirmation-required actions recorded in the audit log yet."

    dec = str(last_entry.get("decision") or last_entry.get("event") or "intercepted").upper()
    cmd_text = last_entry.get("cmd") or last_entry.get("text") or "(unknown)"
    why_text = last_entry.get("why") or last_entry.get("reason") or "policy match"
    risk = last_entry.get("risk_score")
    risk_str = f"{risk:.2f}" if isinstance(risk, (int, float)) else "N/A"
    ts = last_entry.get("ts") or "unknown time"

    lines = [
        f"{ICON} Last Intercepted Action (`{ts}`):",
        f"  • Verdict: **{dec}** (risk score: `{risk_str}`)",
        f"  • Action / Command: `{cmd_text}`",
        f"  • Triggered Rule / Reason: `{why_text}`",
    ]
    if last_entry.get("dry_run_preview"):
        lines.append(f"  • Dry-Run Preview: {last_entry['dry_run_preview']}")
    if dec == "ASK_USER":
        lines.append(
            "  • How to proceed: Reply `confirm` or `yes` in chat (or approve the native IDE dialog) to authorize this single execution."
        )
    else:
        lines.append(
            "  • How to proceed: If this is a safe command for your workflow, add a narrow pattern under `custom_proceed_rules` in `policy.yaml` (or run `python check_action.py --allow \"<regex>\"` in your terminal) and run `/guardrail reload`."
        )
    return "\n".join(lines)


def format_doctor_report(log_path: Path | None = None) -> str:
    """Generate a unified health & diagnostic report for policy, audit log, skills, and daemons."""
    import check_action as ca
    info = ca.reload_policy()
    loaded_path = ca.get_loaded_policy_path() or "policy.yaml (defaults)"
    ok_log, log_msg, _ = verify_audit_log(log_path)

    root_dir = Path(__file__).resolve().parent
    root_skill = root_dir / "SKILL.md"
    skill_Targets = [
        root_dir / ".claude" / "skills" / "guardrail" / "SKILL.md",
        root_dir / ".codex" / "skills" / "guardrail" / "SKILL.md",
        root_dir / ".agents" / "skills" / "guardrail" / "SKILL.md",
        root_dir / ".grok" / "skills" / "guardrail" / "SKILL.md",
    ]
    synced = 0
    if root_skill.is_file():
        root_bytes = root_skill.read_bytes()
        for t in skill_Targets:
            if t.is_file() and t.read_bytes() == root_bytes:
                synced += 1

    lines = [
        f"{ICON} Agent Guardrail Doctor — Unified Health Report:",
        f"  • Policy File: `{loaded_path}` (active backend: `{info['backend']}`)",
        f"  • Loaded Rules: {info['custom_block_rules']} custom block, {info['custom_ask_rules']} custom ask, {info['custom_proceed_rules']} custom proceed, {info['path_rules']} path rules, {info['protected_branches']} protected branches",
        f"  • Audit Log Integrity: {'✔ ' if ok_log else '❌ '}{log_msg}",
        f"  • Workspace Skills Synced: {synced}/{len(skill_Targets)} platforms synchronized with root `SKILL.md`",
    ]
    try:
        import daemon_manager
        lines.append("\n" + daemon_manager.format_status_report())
    except Exception:
        pass
    return "\n".join(lines)


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
    "daemon_manager.py", "install.py", "mcp_server.py", ".guardrail", ".claude/settings.json",
    ".codex/hooks.json", ".agents/hooks.json", ".cursorrules", ".cursor/rules/guardrail.mdc",
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
    if getattr(decision, "risk_factors", None):
        ctx_factors = [f for f in decision.risk_factors if f.startswith("context:")]
        if ctx_factors:
            parts.append("context: " + ", ".join(ctx_factors))
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


def evaluate(description: str, state: State, context=None):
    import check_action as ca

    if state.breaker_open():
        rules = ca.evaluate_rules(description)
        caps = ca.classify_capabilities(description)
        score, factors = ca.compute_risk_score(description, rules, caps, None, context)
        preview = ca.generate_dry_run_preview(description, cwd=(context.cwd if context else ""), capabilities=caps)
        return ca.Decision(
            ca.fallback_decision(description),
            os.environ.get("GUARDRAIL_BACKEND", "clm"),
            rules,
            error="backend cooling down after recent error",
            capabilities=caps,
            risk_score=score,
            risk_factors=factors,
            dry_run_preview=preview,
        )
    result = ca.decide(description, context=context)
    if result.error and result.rules.decision != "block":
        state.trip_breaker()
    return result


# --- Event Handlers ---


def on_prompt_submit(event: dict, host: str, state: State):
    sid = str(event.get("session_id") or "")
    prompt = str(event.get("prompt") or "")
    turn = event.get("turn_id")
    cmd, cmd_arg = parse_command_with_arg(prompt)

    if cmd is not None:
        daemon_msg = ""
        if cmd in ("on", "start"):
            if cmd == "start":
                try:
                    import daemon_manager
                    _, daemon_msg = daemon_manager.start_daemon()
                except Exception as exc:
                    daemon_msg = f"Daemon starter note: {exc}"
            state.update(sid, active=True, pending=None, approved_turn=None, approval_grant=None)
            state.update("_default", active=True, pending=None, approved_turn=None, approval_grant=None)
        elif cmd in ("off", "stop"):
            if cmd == "stop":
                try:
                    import daemon_manager
                    _, daemon_msg = daemon_manager.stop_daemon()
                except Exception as exc:
                    daemon_msg = f"Daemon stop note: {exc}"
            state.update(sid, active=False, pending=None, approved_turn=None, approval_grant=None)
            state.update("_default", active=False, pending=None, approved_turn=None, approval_grant=None)
        elif cmd == "reload":
            import check_action as ca
            reload_info = ca.reload_policy()
            loaded_path = ca.get_loaded_policy_path() or "policy.yaml"
            daemon_msg = (
                f"{ICON} Agent Guardrail policy reloaded from {loaded_path}:\n"
                f"  • Custom rules: {reload_info.get('custom_block_rules', 0)} block, "
                f"{reload_info.get('custom_ask_rules', 0)} ask, "
                f"{reload_info.get('custom_proceed_rules', 0)} proceed, "
                f"{reload_info.get('path_rules', 0)} path rules\n"
                f"  • Protected branches: {reload_info.get('protected_branches', 0)}\n"
                f"  • Dry-run preview: {'enabled' if reload_info.get('dry_run_enabled') else 'disabled'}"
            )
        elif cmd == "check":
            daemon_msg = format_check_report(cmd_arg)
        elif cmd == "why":
            daemon_msg = format_why_report()
        elif cmd == "doctor":
            daemon_msg = format_doctor_report()

        active = is_active(state, sid, host) if cmd in ("status", "reload", "check", "why", "doctor") else (cmd in ("on", "start"))
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
            if cmd in ("reload", "check", "why", "doctor"):
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": daemon_msg,
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
        if cmd in ("reload", "check", "why", "doctor"):
            return {
                "decision": "block",
                "continue": False,
                "stopReason": daemon_msg,
                "reason": daemon_msg,
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
    pending = s.get("pending")
    if host == "codex" and isinstance(pending, dict) and is_confirmation(prompt):
        import check_action as ca
        mem_cfg = ca.get_memory_config()
        confirm_window = float(mem_cfg.get("confirm_window_secs", CONFIRM_WINDOW_SECS))
        now = time.time()
        grant_turn = turn or f"t{now:.0f}"
        grant = {
            "fingerprint": str(pending.get("fingerprint") or ""),
            "text": str(pending.get("text") or ""),
            "tool": str(pending.get("tool") or ""),
            "cwd": str(pending.get("cwd") or ""),
            "turn_id": grant_turn,
            "approved_at": now,
            "expires_at": now + confirm_window,
            "consumed": False,
        }
        state.update(
            sid,
            approved_turn=grant_turn,
            approved_at=now,
            approval_grant=grant,
            pending=None,
        )
        log({
            "host": host,
            "event": "confirm",
            "session": sid,
            "approved_fingerprint": grant["fingerprint"],
            "approved_text": grant["text"],
        })
        return {"hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": (
                f"{ICON} GUARDRAIL: user confirmed. You may execute the exact approved action once this turn "
                "('block' actions and unapproved command modifications remain strictly prohibited)."
            ),
        }}, 0

    result = evaluate(prompt, state)
    log({
        "host": host, "event": "prompt", "session": sid, "text": prompt[:300],
        "decision": result.decision, "risk_score": result.risk_score,
        "capabilities": result.capabilities, "why": result.explain(),
    })

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
            state.update(sid, pending={"text": prompt[:300], "fingerprint": "", "at": time.time()})
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
    if cmd_name.startswith("agent-") or cmd_name.startswith("agent_"):
        cmd_name = cmd_name[6:]
    if cmd_name != "guardrail":
        return None, 0
    sid = str(event.get("session_id") or "")
    raw_args = str(event.get("command_args") or "").strip()
    parts = raw_args.split(" ", 1)
    arg = parts[0].lower()
    rest_arg = parts[1].strip() if len(parts) > 1 else ""
    cmd = _ARG_MAP.get(arg, "on")
    if cmd in ("on", "off"):
        state.update(sid, active=(cmd == "on"), pending=None, approved_turn=None, approval_grant=None)
        state.update("_default", active=(cmd == "on"), pending=None, approved_turn=None, approval_grant=None)
    active = is_active(state, sid, host) if cmd in ("status", "reload", "check", "why", "doctor") else (cmd == "on")
    log({"host": host, "event": "command", "session": sid, "cmd": cmd, "active": active})
    if cmd in ("off", "status"):
        return {"decision": "block", "reason": status_text(active)}, 0
    if cmd == "reload":
        import check_action as ca
        reload_info = ca.reload_policy()
        loaded_path = ca.get_loaded_policy_path() or "policy.yaml"
        msg = (
            f"{ICON} Agent Guardrail policy reloaded from {loaded_path}:\n"
            f"  • Custom rules: {reload_info.get('custom_block_rules', 0)} block, "
            f"{reload_info.get('custom_ask_rules', 0)} ask, "
            f"{reload_info.get('custom_proceed_rules', 0)} proceed, "
            f"{reload_info.get('path_rules', 0)} path rules\n"
            f"  • Protected branches: {reload_info.get('protected_branches', 0)}\n"
            f"  • Dry-run preview: {'enabled' if reload_info.get('dry_run_enabled') else 'disabled'}"
        )
        return {"decision": "block", "reason": msg}, 0
    if cmd == "check":
        return {"decision": "block", "reason": format_check_report(rest_arg)}, 0
    if cmd == "why":
        return {"decision": "block", "reason": format_why_report()}, 0
    if cmd == "doctor":
        return {"decision": "block", "reason": format_doctor_report()}, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptExpansion",
            "additionalContext": (
                f"{status_text(True)}\nInform the user that the guardrail is active. "
                "Do not run manual Python scripts: the guardrail operates in the background via hooks."
            ),
        }
    }, 0


def _extract_read_target(event: dict) -> str:
    """Extract target file path from read/inspection tools for trajectory tracking."""
    if "toolCall" in event and isinstance(event["toolCall"], dict):
        inp = event["toolCall"].get("args") or {}
    else:
        inp = event.get("tool_input") or {}
    if not isinstance(inp, dict):
        return ""
    return str(inp.get("file_path") or inp.get("path") or inp.get("AbsolutePath") or inp.get("TargetFile") or "")


def on_pre_tool(event: dict, host: str, state: State):
    sid = str(event.get("session_id") or event.get("conversationId") or "_default")
    if not is_active(state, sid, host):
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "allow"}, 0
        return None, 0

    import check_action as ca

    desc, safe_shell, paths = describe_tool(event)
    if desc is None:
        # Even for skipped read tools, track if the session accessed a secret file (e.g., .env, id_rsa)
        read_target = _extract_read_target(event)
        if read_target:
            read_caps = ca.classify_capabilities(read_target)
            if "cap:secret_access" in read_caps:
                state.record_action(sid, f"read {read_target}", read_caps)
                log({
                    "host": host, "event": "secret_read_tracked", "session": sid,
                    "text": f"read {read_target}"[:300], "capabilities": read_caps,
                })
        if host in ("antigravity", "agy", "gemini"):
            return {"decision": "allow"}, 0
        return None, 0

    rules = ca.evaluate_rules(desc)
    cwd = str(event.get("cwd") or (event.get("workspacePaths", [""])[0] if event.get("workspacePaths") else ""))
    outside = [p for p in paths if _outside(p, cwd)]
    tool_ident = event.get("tool_name") or (event.get("toolCall", {}).get("name") if isinstance(event.get("toolCall"), dict) else "")

    ctx = ca.inspect_execution_context(
        cwd=cwd,
        outside_cwd=bool(outside),
        prior_capabilities=state.recent_capabilities(sid),
        prior_actions=state.recent_actions(sid),
    )

    if rules.decision == "proceed" and safe_shell:
        caps = ca.classify_capabilities(desc)
        # Ensure safe_shell does not bypass chained secret exfiltration or secret access
        if "cap:secret_access" not in caps and not ("cap:secret_access" in ctx.prior_capabilities and "cap:net_outbound" in caps):
            state.record_action(sid, desc[:160], caps)
            log({
                "host": host, "event": "tool", "session": sid, "tool": tool_ident,
                "text": desc[:300], "decision": "proceed", "risk_score": 0.05,
                "capabilities": caps, "why": "safe read-only command",
            })
            if host in ("antigravity", "agy", "gemini"):
                return {"decision": "allow"}, 0
            return None, 0

    result = evaluate(desc, state, context=ctx)
    final = result.decision
    reason = _reason(result)
    if outside and final == "proceed":
        final, reason = "ask_user", "file outside project directory: " + ", ".join(outside)

    preview = result.dry_run_preview or ca.generate_dry_run_preview(
        desc, cwd=cwd, paths=paths, capabilities=result.capabilities,
    )

    log({
        "host": host, "event": "tool", "session": sid, "tool": tool_ident,
        "text": desc[:300], "decision": final, "risk_score": result.risk_score,
        "capabilities": result.capabilities, "dry_run": preview, "why": result.explain(),
    })

    short = desc.splitlines()[0][:160]
    if final == "block":
        return pre_tool_output(
            host, "deny",
            f"{ICON} GUARDRAIL: action BLOCKED ({reason}; risk={result.risk_score:.2f}): {short}. "
            "Do not retry or attempt bypasses: explain why it was blocked.",
        ), 0

    if final == "ask_user":
        preview_suffix = f" [Dry-Run Preview: {preview}]" if preview else ""
        if host == "claude":
            return pre_tool_output(
                host, "ask",
                f"{ICON} Guardrail: confirmation required ({reason}; risk={result.risk_score:.2f}): {short}{preview_suffix}",
            ), 0
        if host in ("antigravity", "agy", "gemini"):
            return pre_tool_output(
                host, "ask",
                f"{ICON} Guardrail: confirmation required ({reason}; risk={result.risk_score:.2f}): {short}{preview_suffix}",
            ), 0

        s = state.session(sid)
        turn = event.get("turn_id")
        now = time.time()
        curr_fp = compute_action_fingerprint(short, str(tool_ident), cwd)
        grant = s.get("approval_grant")
        mem_cfg = ca.get_memory_config()
        confirm_window = float(mem_cfg.get("confirm_window_secs", CONFIRM_WINDOW_SECS))
        strict_fp = bool(mem_cfg.get("strict_fingerprint", True))

        if isinstance(grant, dict) and not grant.get("consumed", False):
            approved_at = float(grant.get("approved_at", 0))
            expires_at = float(grant.get("expires_at", approved_at + confirm_window))
            grant_turn = grant.get("turn_id")
            turn_ok = bool(
                (turn and grant_turn == turn)
                or (not turn and now <= expires_at)
                or (turn and str(grant_turn or "").startswith("t") and now <= expires_at)
            )
            grant_fp = str(grant.get("fingerprint") or "")
            if strict_fp:
                fp_ok = (grant_fp == curr_fp) if grant_fp else (not grant.get("cwd") or grant.get("cwd") == cwd)
            else:
                fp_ok = (grant_fp == curr_fp) or (not grant.get("cwd") or grant.get("cwd") == cwd)

            if turn_ok and now <= expires_at and fp_ok:
                # Consume single-use approval grant immediately so it never becomes standing authorization
                state.update(sid, approval_grant=None, approved_turn=None, approved_at=None, pending=None)
                state.record_action(sid, short, result.capabilities)
                log({
                    "host": host, "event": "approval_consumed", "session": sid,
                    "tool": tool_ident, "fingerprint": curr_fp, "text": short,
                })
                return None, 0

            # Mismatched action or expired grant -> revoke stale permission immediately
            state.update(sid, approval_grant=None, approved_turn=None, approved_at=None)
            log({
                "host": host, "event": "approval_mismatch", "session": sid,
                "tool": tool_ident, "expected_fp": grant_fp, "actual_fp": curr_fp, "text": short,
            })

        state.update(
            sid,
            pending={
                "text": short,
                "fingerprint": curr_fp,
                "tool": str(tool_ident),
                "cwd": cwd,
                "risk_score": result.risk_score,
                "dry_run": preview,
                "at": now,
            },
        )
        return pre_tool_output(
            host, "deny",
            f"{ICON} GUARDRAIL (ask_user): action paused, user confirmation required ({reason}; risk={result.risk_score:.2f}): {short}{preview_suffix}. "
            "Ask the user if they wish to proceed explaining the risk and dry-run impact. If they confirm, retry the exact same action.",
        ), 0

    state.record_action(sid, short, result.capabilities)
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

    if argv[0] == "reload":
        import check_action as ca
        policy_arg = argv[argv.index("--policy") + 1] if "--policy" in argv else None
        res = ca.reload_policy(policy_arg)
        loaded = ca.get_loaded_policy_path() or "policy.yaml"
        print(f"{ICON} Policy reloaded from {loaded}: {res}")
        return 0

    if argv[0] in ("check", "test"):
        print(format_check_report(" ".join(argv[1:])))
        return 0

    if argv[0] == "why":
        print(format_why_report())
        return 0

    if argv[0] in ("doctor", "health"):
        print(format_doctor_report())
        return 0

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
