#!/usr/bin/env python3
"""What a command really runs: script files and make / npm recipes.

The rules see a command line. `bash deploy.sh`, `python cleanup.py`, `make clean` or `npm run reset`
run code that lives in files, possibly written by the agent a moment earlier. This module finds those
files and recipes and inspects their content:

- scripts the agent wrote or edited in this session are scanned in full: a line that would be blocked
  as a command blocks the run, and file-deletion or upload APIs ask for confirmation;
- make targets and package.json scripts are evaluated like the commands they run (block-level becomes a
  confirmation for the project's own recipes, a block when the agent wrote the Makefile / package.json);
- file-edit tools writing a script get every line checked, not only the first 2000 characters.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import check_action as ca

SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".ksh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs",
               ".ts", ".rb", ".pl", ".php", ".lua"}
SCRIPT_NAMES = {"makefile", "gnumakefile", "dockerfile", "justfile", "package.json", "rakefile", "jenkinsfile"}
_MAX_SCAN_BYTES = 2_000_000

_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_INTERPRETERS = {"python", "python2", "python3", "py", "node", "ruby", "perl", "php", "lua", "tsx", "ts-node", "deno", "bun"}
_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice", "stdbuf", "command", "exec", "setsid"}
_NODE_RUNNERS = {"npm", "pnpm", "yarn", "bun"}

# Inside a script, these APIs delete files or send data out: worth a confirmation when the agent wrote it
_SCRIPT_DANGER: tuple[tuple[str, re.Pattern], ...] = tuple((name, re.compile(rx)) for name, rx in (
    ("file deletion", r"\b(?:os\.(?:remove|unlink|rmdir|removedirs)|shutil\.rmtree|send2trash)\s*\(|\.unlink\s*\(|\.rmdir\s*\("
                      r"|\bfs(?:\.promises)?\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(|\bFileUtils\.(?:rm|rm_r|rm_rf|rm_f|remove_dir)\b"
                      r"|\bRemove-Item\b|\bunlink\s*\("),
    ("upload or network send", r"\brequests\.(?:post|put|patch)\s*\(|\burllib\.request\.(?:urlopen|Request)\s*\(|\bhttpx\.(?:post|put)\s*\("
                               r"|\baxios\.(?:post|put)\s*\(|\bfetch\s*\([^)]*method\s*:\s*['\"](?:POST|PUT)|\bInvoke-(?:RestMethod|WebRequest)\b"
                               r"|\bsocket\.(?:create_connection|socket)\s*\(|\bsmtplib\b"),
))
# Code that imports the guardrail itself can switch it off: never allowed from an agent-run script
GUARDRAIL_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(?:guardrail_hook|check_action|policy_trust|policy_init|git_hooks|readonly_mode|audit_export"
    r"|script_inspect)\b|\b(?:__import__|import_module)\s*\(\s*['\"](?:guardrail_hook|check_action|policy_trust)\b",
    re.MULTILINE,
)


def norm_path(path: str | Path, cwd: str = "") -> str:
    p = Path(os.path.expanduser(str(path).strip("'\"")))
    if not p.is_absolute():
        p = Path(cwd or os.getcwd()) / p
    return os.path.normcase(os.path.abspath(str(p)))


def is_script_path(path: str, content: str = "") -> bool:
    name = os.path.basename(str(path).replace("\\", "/")).lower()
    return os.path.splitext(name)[1] in SCRIPT_EXTS or name in SCRIPT_NAMES or content.lstrip().startswith("#!")


def flag_block_lines(text: str, limit: int = 20) -> list[str]:
    """Lines of text that a block rule (or a guardrail import) matches, searched over the whole text at once."""
    if not text:
        return []
    text = text[:_MAX_SCAN_BYTES]
    found: list[str] = []
    rules = list(ca._COMPILED_BLOCK) + list(ca._CUSTOM_BLOCK) + [("guardrail import", GUARDRAIL_IMPORT_RE)]
    for _name, rx in rules:
        for m in rx.finditer(text):
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            line = text[start:end if end != -1 else len(text)].strip()[:200]
            if line and line not in found:
                found.append(line)
            if len(found) >= limit:
                return found
    return found


def danger_findings(text: str) -> list[str]:
    return [name for name, rx in _SCRIPT_DANGER if rx.search(text or "")]


def _tokens(link: str) -> list[str]:
    toks = [t.strip("'\"") for t in ca._split_tokens(link)]
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        toks = toks[1:]
    while toks and _base(toks[0]) in _WRAPPERS:
        name, toks = _base(toks[0]), toks[1:]
        while toks and (toks[0].startswith("-") or (name == "env" and "=" in toks[0])
                        or (name == "timeout" and re.fullmatch(r"\d+[smhd]?", toks[0]))):
            toks = toks[1:]
    return toks


def _base(tok: str) -> str:
    name = os.path.basename(tok.replace("\\", "/")).lower()
    return name[:-4] if name.endswith(".exe") else name


def _links(command: str) -> list[str]:
    links = ca.split_command_chain(command or "")
    for link in list(links):
        links += [e for e in ca.embedded_commands(link) if e not in links]
    return links


def executed_scripts(command: str, cwd: str = "") -> list[Path]:
    """Script files a command line executes directly (bash x.sh, python x.py, ./x.sh, source x, pwsh -File x.ps1)."""
    found: list[Path] = []
    for link in _links(command):
        toks = _tokens(link)
        if not toks:
            continue
        name, args = _base(toks[0]), toks[1:]
        candidates: list[str] = []
        if name in _SHELLS or name in _INTERPRETERS:
            if any(a in ("-c", "-e", "-r", "--eval", "-m") for a in args):
                continue
            plain = [a for a in args if not a.startswith("-")]
            if name == "bun" and plain[:1] == ["run"]:
                plain = plain[1:]
            candidates = plain[:1]
        elif name in ("powershell", "pwsh"):
            low = [a.lower() for a in args]
            if "-file" in low and low.index("-file") + 1 < len(args):
                candidates = [args[low.index("-file") + 1]]
            else:
                candidates = [a for a in args if a.lower().endswith(".ps1")][:1]
        elif name in ("source", "."):
            candidates = args[:1]
        elif os.path.splitext(name)[1] in SCRIPT_EXTS or toks[0].startswith(("./", "../", "/", ".\\")):
            candidates = toks[:1]
        for c in candidates:
            p = Path(norm_path(c, cwd))
            if p.is_file() and p not in found:
                found.append(p)
    return found


def _make_recipes(makefile: Path, targets: list[str], depth: int = 0) -> list[tuple[str, str]]:
    try:
        text = makefile.read_text(encoding="utf-8", errors="ignore")[:_MAX_SCAN_BYTES]
    except OSError:
        return []
    rules: dict[str, tuple[list[str], list[str]]] = {}
    order: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_./%-][^:=\s]*(?:\s+[^:=\s]+)*)\s*::?(?!=)\s*(.*)$", line)
        if m and not line.startswith("\t"):
            current = m.group(1).split()
            prereqs = m.group(2).split(";")[0].split()
            for t in current:
                rules.setdefault(t, ([], []))[0].extend(prereqs)
                if not t.startswith(".") and t not in order:
                    order.append(t)
        elif line.startswith("\t") and current:
            for t in current:
                rules.setdefault(t, ([], []))[1].append(line.strip().lstrip("@-+").strip())
        elif line.strip() and not line.startswith("\t"):
            current = []
    wanted = targets or order[:1]
    out: list[tuple[str, str]] = []
    for t in wanted:
        prereqs, recipe = rules.get(t, ([], []))
        if recipe:
            out.append((f"make {t}", "\n".join(recipe)))
        deps = [p for p in prereqs if p in rules]
        if depth < 2 and deps:  # an empty list would mean "the default target"
            out += _make_recipes(makefile, deps, depth + 1)
    return out


def recipes_for(command: str, cwd: str = "") -> list[tuple[str, str, Path]]:
    """(label, body, defining file) for make targets and package.json scripts a command line runs."""
    base = Path(cwd or os.getcwd())
    out: list[tuple[str, str, Path]] = []
    for link in _links(command):
        toks = _tokens(link)
        if not toks:
            continue
        name, args = _base(toks[0]), toks[1:]
        if name in ("make", "gmake"):
            makefile = next((base / n for n in ("GNUmakefile", "makefile", "Makefile") if (base / n).is_file()), None)
            if makefile:
                targets = [a for a in args if not a.startswith("-") and "=" not in a]
                out += [(label, body, makefile) for label, body in _make_recipes(makefile, targets)]
        elif name in _NODE_RUNNERS:
            pkg = base / "package.json"
            if not pkg.is_file():
                continue
            plain = [a for a in args if not a.startswith("-")]
            script = ""
            if plain[:1] in (["run"], ["run-script"]) and len(plain) > 1:
                script = plain[1]
            elif plain[:1] in (["test"], ["start"], ["stop"], ["restart"]):
                script = plain[0]
            elif name in ("yarn", "pnpm") and plain and plain[0] not in ("add", "remove", "install", "upgrade", "up", "dlx", "exec", "why", "info"):
                script = plain[0]
            if not script:
                continue
            try:
                scripts = json.loads(pkg.read_text(encoding="utf-8", errors="ignore")).get("scripts") or {}
            except (OSError, ValueError):
                continue
            for key in (f"pre{script}", script, f"post{script}"):
                if isinstance(scripts.get(key), str):
                    out.append((f"{name} script \"{key}\"", scripts[key], pkg))
    return out


# Ask-level rules that are too noisy to raise for a recipe (words like "config" or "production" are everywhere)
_QUIET_RECIPE_TAGS = {"ask_user:config / deploy", "ask_user:vague instruction", "ask_user:confirmation requested",
                      "ask_user:payments", "ask_user:external comms", "ask_user:overwrite"}


def inspect_execution(command: str, cwd: str = "", written: set[str] | None = None) -> tuple[str, list[str]]:
    """('block' | 'ask_user' | 'proceed', reasons) for the code a shell command runs indirectly."""
    written = written or set()
    decision, reasons = "proceed", []

    def raise_to(level: str, why: str) -> None:
        nonlocal decision
        decision = ca.most_severe(decision, level)
        reasons.append(why)

    for script in executed_scripts(command, cwd):
        mine = os.path.normcase(str(script)) in written
        try:
            text = script.read_text(encoding="utf-8", errors="ignore")[:_MAX_SCAN_BYTES]
        except OSError:
            continue
        if GUARDRAIL_IMPORT_RE.search(text):
            raise_to("block", f"{script.name} imports the guardrail's own modules")
        flagged = flag_block_lines(text, limit=3)
        if flagged:
            level = "block" if mine else "ask_user"
            origin = "written in this session" if mine else "a script in the project"
            raise_to(level, f"{script.name} ({origin}) runs a blocked command: {flagged[0]}")
        if mine:
            for name in danger_findings(text):
                raise_to("ask_user", f"{script.name} (written in this session) uses {name} APIs")

    for label, body, source in recipes_for(command, cwd):
        mine = os.path.normcase(str(source)) in written
        r = ca.evaluate_rules(body)
        if r.decision == "block":
            raise_to("block" if mine else "ask_user",
                     f"{label} runs a blocked command" + (" (file written in this session)" if mine else "") + f": {body.splitlines()[0][:120]}")
        elif r.decision == "ask_user":
            loud = [m for m in r.matched if m not in _QUIET_RECIPE_TAGS]
            if loud:
                raise_to("ask_user", f"{label} runs: {body.splitlines()[0][:120]} ({', '.join(m.split(':', 1)[1] for m in loud[:2])})")
    return decision, reasons
