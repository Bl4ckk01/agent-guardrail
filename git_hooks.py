#!/usr/bin/env python3
"""Git pre-commit credential scan (`python install.py --git-hook`).

Scans what is staged for commit: secret files (.env, id_rsa, *.pem...) and added lines containing a
credential value (AWS/GitHub/Slack/... tokens, private key blocks). It covers commits made by hand or by
any tool, not only the agent's. Findings never print the credential itself.

A line can opt out with the marker `guardrail:ignore` (test fixtures, documentation).
`git commit --no-verify` skips the hook, as for any git hook.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import check_action as ca

MARKER_BEGIN = "# >>> agent-guardrail pre-commit >>>"
MARKER_END = "# <<< agent-guardrail pre-commit <<<"
IGNORE_MARKER = "guardrail:ignore"
_MAX_DIFF_BYTES = 20_000_000


def _git(args: list[str], cwd: str | Path | None = None) -> str:
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args], cwd=str(cwd) if cwd else None,
        capture_output=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace").strip() or f"git {args[0]} failed")
    return proc.stdout[:_MAX_DIFF_BYTES].decode("utf-8", errors="replace")


def staged_findings(cwd: str | Path | None = None) -> list[dict]:
    """Findings in the staged changes: {file, line, kind}; `line` is 0 for a secret file name."""
    findings: list[dict] = []
    names = [n for n in _git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], cwd).split("\0") if n]
    for n in names:
        if ca.is_secret_path(n):
            findings.append({"file": n, "line": 0, "kind": "secret file"})

    current, line_no = "", 0
    for raw in _git(["diff", "--cached", "--no-color", "-U0", "--diff-filter=ACMR"], cwd).splitlines():
        if raw.startswith("+++ "):
            current = raw[6:] if raw.startswith("+++ b/") else ""
            continue
        m = re.match(r"^@@ -\S+ \+(\d+)(?:,\d+)? @@", raw)
        if m:
            line_no = int(m.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            text = raw[1:]
            if current and IGNORE_MARKER not in text:
                for kind in ca.find_secret_values(text):
                    findings.append({"file": current, "line": line_no, "kind": kind})
            line_no += 1
    return findings


def format_findings(findings: list[dict]) -> str:
    lines = [f"agent-guardrail: commit blocked, {len(findings)} credential finding(s) in the staged changes:"]
    for f in findings[:30]:
        where = f["file"] if not f["line"] else f"{f['file']}:{f['line']}"
        lines.append(f"  - {where}: {f['kind']}")
    if len(findings) > 30:
        lines.append(f"  ... and {len(findings) - 30} more")
    lines += [
        "Remove the credential (use an environment variable or a secret manager) and rotate it if it was ever shared.",
        f"A line that is not a real credential can carry the marker `{IGNORE_MARKER}`; `git commit --no-verify` skips this check.",
    ]
    return "\n".join(lines)


def scan_staged(cwd: str | Path | None = None) -> tuple[int, str]:
    """(exit code, report) for the pre-commit hook. A scanner failure never blocks a commit."""
    try:
        findings = staged_findings(cwd)
    except (RuntimeError, OSError) as exc:
        return 0, f"agent-guardrail: pre-commit scan skipped ({exc})"
    if findings:
        return 1, format_findings(findings)
    return 0, ""


def _write_lf(path: Path, text: str) -> None:
    """Hook scripts must keep LF endings (sh rejects CRLF) on Windows too."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def hooks_dir(repo: str | Path) -> Path:
    path = _git(["rev-parse", "--git-path", "hooks"], repo).strip()
    p = Path(path)
    return p if p.is_absolute() else Path(repo) / p


def install_pre_commit(repo: str | Path, python: str | None = None) -> tuple[bool, str]:
    """Add the scan to the repository's pre-commit hook, keeping any existing hook content."""
    try:
        hdir = hooks_dir(repo)
    except (RuntimeError, OSError) as exc:
        return False, f"{repo} is not a git repository ({exc})"
    script = Path(__file__).resolve().parent / "guardrail_hook.py"
    py = (python or sys.executable or "python").replace("\\", "/")
    block = (
        f"{MARKER_BEGIN}\n"
        f'"{py}" "{str(script).replace(chr(92), "/")}" scan-staged || exit 1\n'
        f"{MARKER_END}\n"
    )
    target = hdir / "pre-commit"
    try:
        hdir.mkdir(parents=True, exist_ok=True)
        existing = target.read_text(encoding="utf-8") if target.is_file() else ""
        if MARKER_BEGIN in existing:
            existing = re.sub(re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END) + r"\n?", "", existing, flags=re.DOTALL)
        base = existing if existing.strip() else "#!/bin/sh\n"
        if not base.startswith("#!"):
            base = "#!/bin/sh\n" + base
        _write_lf(target, base.rstrip("\n") + "\n\n" + block)
        try:
            target.chmod(target.stat().st_mode | 0o111)
        except OSError:
            pass
    except OSError as exc:
        return False, f"could not write {target}: {exc}"
    return True, f"pre-commit credential scan installed in {target}"


def uninstall_pre_commit(repo: str | Path) -> tuple[bool, str]:
    try:
        target = hooks_dir(repo) / "pre-commit"
        text = target.read_text(encoding="utf-8") if target.is_file() else ""
    except (RuntimeError, OSError) as exc:
        return False, str(exc)
    if MARKER_BEGIN not in text:
        return False, "no agent-guardrail block in the pre-commit hook"
    cleaned = re.sub(re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END) + r"\n?", "", text, flags=re.DOTALL).rstrip("\n") + "\n"
    if cleaned.strip() in ("", "#!/bin/sh"):
        target.unlink()
    else:
        _write_lf(target, cleaned)
    return True, f"agent-guardrail block removed from {target}"


if __name__ == "__main__":
    code, report = scan_staged(os.getcwd())
    if report:
        print(report, file=sys.stderr if code else sys.stdout)
    sys.exit(code)
