#!/usr/bin/env python3
"""Hash-pinned trust for a project's policy.yaml (`/guardrail trust`).

A policy.yaml in the project directory is content an agent could have written, so by default it can only
make the guardrail stricter. After the user reviews it and approves its exact SHA-256 in chat, it may
also whitelist commands for that project (narrow `custom_proceed_rules`, `proceed` path rules). Any
change to the file drops the trust until it is approved again. Everything else stays off limits to a
project policy: audit logging, backend settings, network allowlist, modes, thresholds.

The approval is a chat command (typed by the user, never a tool call) and this module has no command
line entry point; the store file is protected like the rest of the guardrail's control plane.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import check_action as ca

MIN_CONFIRM_CHARS = 6


def store_path() -> Path:
    home = Path(os.environ.get("GUARDRAIL_HOME", Path.home() / ".guardrail"))
    return home / "trusted_policies.json"


def _key(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load() -> dict:
    try:
        data = json.loads(store_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    target = store_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def status(path: str | Path) -> str:
    """'trusted', 'changed' (approved once, edited since) or 'untrusted'."""
    entry = _load().get(_key(path))
    if not isinstance(entry, dict):
        return "untrusted"
    try:
        return "trusted" if entry.get("sha256") == file_sha256(path) else "changed"
    except OSError:
        return "untrusted"


def is_trusted(path: str | Path) -> bool:
    return status(path) == "trusted"


def inspect(path: str | Path) -> dict:
    """What a project policy would be allowed to whitelist once trusted."""
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rules, ignored = [], []
    for r in (data.get("custom_proceed_rules") or []):
        if not isinstance(r, dict) or not r.get("pattern"):
            continue
        ok, msg, _ = ca.validate_allow_pattern(str(r["pattern"]))
        (rules if ok else ignored).append({"name": str(r.get("name", "custom_proceed")), "pattern": str(r["pattern"]),
                                           "why": msg})
    paths = [{"name": str(r.get("name", "")), "path": str(r.get("path", ""))}
             for r in (data.get("path_rules") or data.get("custom_path_rules") or [])
             if isinstance(r, dict) and str(r.get("decision", "")).lower() == "proceed" and r.get("path")]
    sha = file_sha256(path)
    return {"sha256": sha, "short": sha[:8], "proceed_rules": rules, "ignored_rules": ignored, "proceed_paths": paths}


def _describe(path: Path, info: dict) -> str:
    lines = [f"Project policy {path} (sha256 {info['short']}…):"]
    if info["proceed_rules"]:
        lines.append("  It would be allowed to whitelist, for this project:")
        lines += [f"    - {r['name']}: `{r['pattern']}`" for r in info["proceed_rules"][:15]]
    else:
        lines.append("  It adds no safe-command rules.")
    for p in info["proceed_paths"][:10]:
        lines.append(f"    - any command touching `{p['path']}` ({p['name'] or 'path rule'})")
    for r in info["ignored_rules"][:5]:
        lines.append(f"  Ignored (too broad or invalid): `{r['pattern']}` — {r['why']}")
    lines.append("  Block and ask rules, tighter limits and tests from this file apply with or without trust.")
    return "\n".join(lines)


def request_trust(path: str | Path, confirm: str = "") -> str:
    """Two steps: show what the file would be allowed to do, then pin the hash the user typed back."""
    p = Path(path)
    if not p.is_file():
        return f"No policy.yaml in {p.parent}."
    try:
        info = inspect(p)
    except Exception as exc:  # unreadable or invalid YAML
        return f"Cannot read {p}: {exc}"
    wanted = (confirm or "").strip().lower()
    if not wanted:
        return (_describe(p, info) + f"\n  To approve exactly this version, type `/guardrail trust {info['short']}`."
                "\n  Any later edit of the file removes the approval.")
    if len(wanted) < MIN_CONFIRM_CHARS or not info["sha256"].startswith(wanted):
        return (f"Not approved: `{wanted}` does not match the file as it is now ({info['short']}…). "
                "It may have changed since you reviewed it: run `/guardrail trust` again.")
    store = _load()
    store[_key(p)] = {"sha256": info["sha256"], "approved_at": time.time(), "rules": len(info["proceed_rules"])}
    _save(store)
    return (f"Project policy {p} is trusted (sha256 {info['short']}…): its {len(info['proceed_rules'])} safe-command "
            f"rule(s) apply to this project. Run `/guardrail reload` to load them now; revoke with `/guardrail trust revoke`.")


def revoke(path: str | Path) -> str:
    store = _load()
    if store.pop(_key(path), None) is None:
        return "That policy.yaml was not trusted."
    _save(store)
    return f"Trust removed for {path}. It can only tighten the guardrail again."


def list_trusted() -> str:
    store = _load()
    if not store:
        return "No project policy is trusted."
    lines = ["Trusted project policies:"]
    for key, entry in store.items():
        state = "ok" if Path(key).is_file() and entry.get("sha256") == file_sha256(key) else "changed or missing"
        lines.append(f"  - {key} ({str(entry.get('sha256', ''))[:8]}…, {entry.get('rules', 0)} rule(s), {state})")
    return "\n".join(lines)


def handle_command(cwd: str | Path, arg: str) -> str:
    """`/guardrail trust [<hash>|list|revoke]` for the policy.yaml of the project in cwd."""
    word = (arg or "").strip().lower()
    policy = Path(cwd) / "policy.yaml"
    here = ca.get_loaded_policy_path()
    if policy.is_file() and here is not None:
        try:
            if policy.resolve() == Path(here).resolve():
                return "This is the guardrail's own policy.yaml: it is always trusted."
        except OSError:
            pass
    if word in ("list", "ls"):
        return list_trusted()
    if word in ("revoke", "remove", "untrust", "off"):
        return revoke(policy)
    return request_trust(policy, word)
