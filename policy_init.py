#!/usr/bin/env python3
"""Stack-aware policy proposals (`/guardrail init`).

Looks at the project (package.json, pyproject.toml, Cargo.toml, go.mod, Makefile, compose files),
proposes narrow `custom_proceed_rules` for its routine check/lint/test/build commands, and the matching
`tests:` cases. Commands that are already whitelisted or blocked are not proposed.

Reading and proposing is harmless and can run from chat. Applying edits the trusted policy.yaml,
so it is a terminal step for the human: `python guardrail_hook.py init --apply`.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import check_action as ca

# Script/target names that only inspect or build: never dev servers, deploys, cleaners or publishers
_SAFE_NAME_RE = re.compile(
    r"^(?:test|tests|lint|check|typecheck|type-check|tsc|build|validate|verify|format:check|fmt:check|prettier:check"
    r"|test:[\w:-]+|lint:[\w:-]+|check:[\w:-]+)$"
)
# Anything in a script body that touches the network, deletes, installs or deploys disqualifies it
_UNSAFE_BODY_RE = re.compile(
    r"\b(?:rm|rmdir|del|curl|wget|ssh|scp|sudo|deploy|publish|push|install|migrate|drop|truncate|kill|docker|kubectl"
    r"|terraform|release)\b|npm\s+ci\b|--fix\b|--write\b|-w\b",
    re.IGNORECASE,
)
_MAX_SCRIPTS = 8


@dataclass
class Proposal:
    name: str
    pattern: str
    sample: str
    why: str


def _read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _node(root: Path) -> tuple[list[str], list[Proposal]]:
    pkg = root / "package.json"
    if not pkg.is_file():
        return [], []
    try:
        scripts = json.loads(_read_text(pkg)).get("scripts") or {}
    except ValueError:
        return ["node"], []
    if (root / "yarn.lock").is_file():
        pm, run_rx, run = "yarn", r"\byarn\s+(?:run\s+)?", "yarn"
    elif (root / "pnpm-lock.yaml").is_file():
        pm, run_rx, run = "pnpm", r"\bpnpm\s+(?:run\s+)?", "pnpm"
    elif (root / "bun.lockb").is_file() or (root / "bun.lock").is_file():
        pm, run_rx, run = "bun", r"\bbun\s+run\s+", "bun run"
    else:
        pm, run_rx, run = "npm", r"\bnpm\s+run\s+", "npm run"
    out: list[Proposal] = []
    for name, body in scripts.items():
        if not isinstance(body, str) or not _SAFE_NAME_RE.match(name) or _UNSAFE_BODY_RE.search(body):
            continue
        out.append(Proposal(
            f"{pm} script: {name}", run_rx + re.escape(name) + r"\b", f"{run} {name}",
            f'package.json script "{name}" (`{body[:60]}`)',
        ))
    return ["node"], out[:_MAX_SCRIPTS]


def _python(root: Path) -> tuple[list[str], list[Proposal]]:
    files = [root / n for n in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "tox.ini", "pytest.ini", "noxfile.py")]
    if not any(f.is_file() for f in files):
        return [], []
    cfg = _read_text(root / "pyproject.toml") + _read_text(root / "setup.cfg") + _read_text(root / "tox.ini")
    out: list[Proposal] = [
        Proposal("python unittest", r"\bpython\d?\s+-m\s+unittest\b", "python -m unittest discover", "stdlib test runner"),
    ]
    if "[tool.ruff" in cfg or (root / "ruff.toml").is_file() or (root / ".ruff.toml").is_file():
        out.append(Proposal("ruff format check", r"\bruff\s+format\s+--check\b", "ruff format --check .", "ruff is configured"))
    if "[tool.black" in cfg:
        out.append(Proposal("black check", r"\bblack\s+--check\b", "black --check .", "black is configured"))
    if "[tool.isort" in cfg or "isort" in cfg:
        out.append(Proposal("isort check", r"\bisort\s+--check(?:-only)?\b", "isort --check-only .", "isort is configured"))
    if (root / "tox.ini").is_file():
        out.append(Proposal("tox", r"\btox\b(?!\s+(?:-e\s+\S*(?:deploy|publish|release)))", "tox", "tox.ini present"))
    if (root / "noxfile.py").is_file():
        out.append(Proposal("nox", r"\bnox\b", "nox", "noxfile.py present"))
    return ["python"], out


def _rust(root: Path) -> tuple[list[str], list[Proposal]]:
    if not (root / "Cargo.toml").is_file():
        return [], []
    return ["rust"], [
        Proposal("cargo clippy", r"\bcargo\s+clippy\b(?!.*--fix)", "cargo clippy", "Cargo.toml present"),
        Proposal("cargo fmt check", r"\bcargo\s+fmt\s+(?:--all\s+)?--check\b", "cargo fmt --check", "Cargo.toml present"),
    ]


def _go(root: Path) -> tuple[list[str], list[Proposal]]:
    if not (root / "go.mod").is_file():
        return [], []
    return ["go"], [
        Proposal("go build", r"\bgo\s+build\b", "go build ./...", "go.mod present"),
        Proposal("gofmt list", r"\bgofmt\s+-l\b", "gofmt -l .", "go.mod present"),
        Proposal("golangci-lint", r"\bgolangci-lint\s+run\b", "golangci-lint run", "go.mod present"),
    ]


def _make(root: Path) -> tuple[list[str], list[Proposal]]:
    mk = root / "Makefile"
    if not mk.is_file():
        return [], []
    out: list[Proposal] = []
    for m in re.finditer(r"^([A-Za-z][\w:-]*)\s*:(?!=)", _read_text(mk), re.MULTILINE):
        name = m.group(1)
        if _SAFE_NAME_RE.match(name):
            # The recipe is not inspected: only proposed for the conventional check-like target names
            out.append(Proposal(f"make {name}", r"\bmake\s+" + re.escape(name) + r"\b", f"make {name}",
                                f'Makefile target "{name}" (review the recipe first)'))
    return ["make"], out[:_MAX_SCRIPTS]


def _compose(root: Path) -> tuple[list[str], list[Proposal]]:
    if not any((root / n).is_file() for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")):
        return [], []
    return ["docker compose"], [
        Proposal("compose read-only", r"\bdocker[\s-]compose\s+(?:ps|logs|config|images|ls|top)\b",
                 "docker compose ps", "compose file present: inspect services without changing them"),
    ]


_DETECTORS = (_node, _python, _rust, _go, _make, _compose)

# Always-true expectations that guard the baseline against a bad future edit
_BASELINE_TESTS = (
    {"action": "rm -rf build/", "expect": "block"},
    {"action": "git push --force origin main", "expect": "block"},
    {"action": "ls $(rm notes.txt)", "expect": "ask_user"},
)


def detect(root: str | Path) -> dict:
    """Stacks found in root, plus the proposals that would change today's decisions."""
    base = Path(root)
    stacks: list[str] = []
    proposals: list[Proposal] = []
    for detector in _DETECTORS:
        found, props = detector(base)
        stacks += found
        proposals += props
    useful: list[Proposal] = []
    already: list[Proposal] = []
    seen: set[str] = set()
    for p in proposals:
        ok, _, _ = ca.validate_allow_pattern(p.pattern)
        if not ok or p.pattern in seen:
            continue
        seen.add(p.pattern)
        # Skip what is already whitelisted and anything blocked outright. A command no rule matches is still
        # worth whitelisting: it asks today, or is left to the model backend, which may ask
        current = ca.evaluate_rules(p.sample)
        if current.decision == "block":
            continue
        (already if any(m.startswith("proceed:") for m in current.matched) else useful).append(p)
    return {"root": str(base), "stacks": stacks, "proposals": useful, "already_allowed": already}


def _yaml_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_proposal(info: dict) -> str:
    """The proposal as a policy.yaml fragment (custom_proceed_rules + tests)."""
    lines = ["# Proposed by /guardrail init for: " + (", ".join(info["stacks"]) or "unknown stack"), "custom_proceed_rules:"]
    for p in info["proposals"]:
        lines += [f"  - name: {_yaml_str('init: ' + p.name)}", f"    pattern: {_yaml_str(p.pattern)}"]
    lines.append("tests:")
    for p in info["proposals"]:
        lines += [f"  - action: {_yaml_str(p.sample)}", "    expect: proceed"]
    for t in _BASELINE_TESTS:
        lines += [f"  - action: {_yaml_str(t['action'])}", f"    expect: {t['expect']}"]
    return "\n".join(lines) + "\n"


def proposal_path() -> Path:
    home = Path(os.environ.get("GUARDRAIL_HOME", Path.home() / ".guardrail"))
    return home / "policy.proposed.yaml"


def format_init_report(root: str | Path) -> str:
    """Human-readable proposal; also saved to GUARDRAIL_HOME/policy.proposed.yaml for review."""
    info = detect(root)
    if not info["stacks"]:
        return ("Guardrail init: no known project files found in "
                f"{info['root']} (package.json, pyproject.toml, Cargo.toml, go.mod, Makefile, compose file).")
    lines = [f"Guardrail init for {info['root']} (detected: {', '.join(info['stacks'])}):"]
    if info["already_allowed"]:
        lines.append(f"  • Already allowed without confirmation: {len(info['already_allowed'])} command(s) "
                     f"(e.g. `{info['already_allowed'][0].sample}`).")
    if not info["proposals"]:
        lines.append("  • Nothing to add: the routine commands of this project already pass.")
        return "\n".join(lines)
    lines.append("  • Proposed safe rules (not whitelisted yet: they ask, or are left to the model backend):")
    for p in info["proposals"]:
        lines.append(f"      `{p.sample}` — {p.why}")
    try:
        target = proposal_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_proposal(info), encoding="utf-8")
        lines.append(f"  • Saved for review: {target}")
    except OSError:
        pass
    lines.append("  • To adopt them, run in YOUR terminal (rules and tests go into the trusted policy.yaml):")
    lines.append(f'      python guardrail_hook.py init "{info["root"]}" --apply')
    lines.append("    then `/guardrail reload` and `/guardrail test`. Rules are not applied from chat on purpose.")
    return "\n".join(lines)


def _add_tests(cases: list[dict], policy_file: Path) -> int:
    """Append test cases under the `tests:` key of policy.yaml (textual insert keeps comments intact)."""
    content = policy_file.read_text(encoding="utf-8")
    existing = set(re.findall(r"^\s*-\s*action:\s*(.+?)\s*$", content, re.MULTILINE))
    new = [c for c in cases if _yaml_str(c["action"]) not in existing and f'"{c["action"]}"' not in existing]
    if not new:
        return 0
    block = "".join(f"  - action: {_yaml_str(c['action'])}\n    expect: {c['expect']}\n" for c in new)
    m = re.search(r"^tests:[ \t]*\n", content, re.MULTILINE)
    if m:
        content = content[:m.end()] + block + content[m.end():]
    else:
        content = content.rstrip() + "\n\ntests:\n" + block
    policy_file.write_text(content, encoding="utf-8")
    return len(new)


def apply_proposal(root: str | Path) -> str:
    """Write the proposed rules and tests into the trusted policy.yaml (human terminal step)."""
    info = detect(root)
    if not info["proposals"]:
        return "Guardrail init: nothing to apply."
    target = ca._find_policy_file(None) or (Path(ca.__file__).resolve().parent / "policy.yaml")
    added, skipped = [], []
    for p in info["proposals"]:
        ok, msg = ca.allow_custom_rule(p.pattern, name=f"init: {p.name}", policy_file=target)
        (added if ok else skipped).append(p.name if ok else f"{p.name} ({msg})")
    cases = [{"action": p.sample, "expect": "proceed"} for p in info["proposals"]] + list(_BASELINE_TESTS)
    n_tests = _add_tests(cases, target)
    ca.reload_policy()
    results = ca.run_policy_tests()
    failed = [r for r in results if not r["ok"]]
    lines = [f"Guardrail init applied to {target}:",
             f"  • {len(added)} rule(s) added, {n_tests} test case(s) added"]
    lines += [f"  • skipped: {s}" for s in skipped]
    lines.append(f"  • policy tests: {len(results) - len(failed)}/{len(results)} passed")
    lines += [f"  • FAILED `{r['action']}`: expected {r['expect']}, got {r['got']}" for r in failed]
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    root_arg = args[0] if args else os.getcwd()
    print(apply_proposal(root_arg) if "--apply" in sys.argv else format_init_report(root_arg))
