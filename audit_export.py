#!/usr/bin/env python3
"""Audit report export (`/guardrail export [json|html|csv] [days]`).

Turns the audit log entries (already redacted when they were written) into a file that can be attached
to a review: a summary, the integrity status of the hash chain, and one row per action that asked for
confirmation, was blocked, or is a notable event. HTML is self-contained and escapes everything; CSV
cells that a spreadsheet would execute as formulas are neutralized.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
import time
from collections import Counter
from pathlib import Path

FORMATS = ("json", "html", "csv")
_NOTABLE = {
    "secret_read_tracked", "secret_output_tracked", "injection_suspected", "auto_escalated", "temp_allow_used",
    "temp_allow_added", "approval_consumed", "approval_mismatch", "backup", "undo", "mode_changed",
    "readonly_changed", "log_rotated", "self_tamper", "chained_exfil",
}
_MAX_ROWS = 2000


def _ts(entry: dict) -> float | None:
    try:
        return time.mktime(time.strptime(str(entry.get("ts", "")), "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def collect(entries: list[dict], days: float = 7, chain: tuple[bool, str] | None = None) -> dict:
    """Summary and rows for the entries of the last `days` days."""
    cutoff = time.time() - days * 86400
    decisions: Counter = Counter()
    events: Counter = Counter()
    rules: Counter = Counter()
    sessions: set[str] = set()
    rows: list[dict] = []
    for e in entries:
        ts = _ts(e)
        if ts is None or ts < cutoff:
            continue
        event = str(e.get("event") or "")
        events[event] += 1
        if e.get("session"):
            sessions.add(str(e["session"]))
        decision = e.get("decision") if event in ("tool", "prompt") else None
        if decision in ("proceed", "ask_user", "block"):
            decisions[decision] += 1
        matched = [str(r) for r in (e.get("matched_rules") or []) if not str(r).startswith("proceed:")]
        if decision in ("ask_user", "block"):
            rules.update(matched)
        if decision in ("ask_user", "block") or event in _NOTABLE:
            rows.append({
                "time": str(e.get("ts", "")), "session": str(e.get("session") or "")[:12], "event": event,
                "decision": str(decision or ""), "tool": str(e.get("tool") or ""),
                "text": str(e.get("text") or e.get("pattern") or e.get("archive") or "")[:200].replace("\n", " "),
                "rules": ", ".join(matched)[:200],
            })
    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "days": days,
        "summary": {
            "evaluated": sum(decisions.values()), "proceed": decisions["proceed"], "ask_user": decisions["ask_user"],
            "block": decisions["block"], "sessions": len(sessions),
            "events": {k: v for k, v in sorted(events.items()) if k in _NOTABLE},
            "top_rules": [{"rule": r.split(":", 1)[-1], "count": n} for r, n in rules.most_common(10)],
        },
        "audit_chain": {"ok": chain[0], "detail": chain[1]} if chain else None,
        "rows_truncated": max(0, len(rows) - _MAX_ROWS),
        "events": rows[-_MAX_ROWS:],
    }


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _csv_cell(value: str) -> str:
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def render_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    columns = ["time", "session", "event", "decision", "tool", "text", "rules"]
    writer.writerow(columns)
    for row in data["events"]:
        writer.writerow([_csv_cell(str(row[c])) for c in columns])
    return buf.getvalue()


def render_html(data: dict) -> str:
    e = html.escape
    s = data["summary"]
    chain = data.get("audit_chain")
    chain_html = ""
    if chain:
        chain_html = f'<p class="{"ok" if chain["ok"] else "bad"}">Audit log integrity: {e(chain["detail"])}</p>'
    top = "".join(f"<li>{n['count']}&times; {e(n['rule'])}</li>" for n in s["top_rules"]) or "<li>none</li>"
    notable = "".join(f"<li>{e(k)}: {v}</li>" for k, v in s["events"].items()) or "<li>none</li>"
    body = "".join(
        "<tr>" + "".join(f"<td>{e(str(r[c]))}</td>" for c in ("time", "session", "event", "decision", "tool", "text", "rules")) + "</tr>"
        for r in data["events"]
    )
    note = f"<p>{data['rows_truncated']} older rows omitted.</p>" if data["rows_truncated"] else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Guardrail report</title>
<style>
:root{{--bg:#fff;--fg:#1c1c1e;--muted:#6b6b70;--line:#d8d8dc;--ok:#1a7f37;--bad:#c62828}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16161a;--fg:#ececf1;--muted:#9a9aa3;--line:#33333a;--ok:#4cc38a;--bad:#ff6b6b}}}}
body{{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;max-width:1100px;margin-inline:auto}}
h1{{font-size:1.4rem;margin:0 0 4px}} .muted{{color:var(--muted)}} .ok{{color:var(--ok)}} .bad{{color:var(--bad)}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}} .card{{border:1px solid var(--line);border-radius:8px;padding:10px 16px}}
.card b{{display:block;font-size:1.5rem}} table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}}
.wrap{{overflow-x:auto}}
</style></head><body>
<h1>Agent Guardrail report</h1>
<p class="muted">Last {e(f"{data['days']:g}")} day(s), generated {e(data['generated'])}, {s['sessions']} session(s).</p>
{chain_html}
<div class="cards">
<div class="card"><b>{s['evaluated']}</b>evaluated</div><div class="card"><b>{s['proceed']}</b>proceed</div>
<div class="card"><b>{s['ask_user']}</b>asked</div><div class="card"><b>{s['block']}</b>blocked</div>
</div>
<h2>Most frequent block/ask rules</h2><ul>{top}</ul>
<h2>Notable events</h2><ul>{notable}</ul>
<h2>Actions that asked, were blocked, or matter</h2>{note}
<div class="wrap"><table><thead><tr><th>Time</th><th>Session</th><th>Event</th><th>Decision</th><th>Tool</th><th>Action</th><th>Rules</th></tr></thead>
<tbody>{body}</tbody></table></div>
</body></html>
"""


def export_report(entries: list[dict], days: float = 7, fmt: str = "html", chain: tuple[bool, str] | None = None,
                  out_dir: str | Path | None = None) -> Path:
    fmt = fmt.lower()
    if fmt not in FORMATS:
        raise ValueError(f"unknown format '{fmt}' (use {', '.join(FORMATS)})")
    data = collect(entries, days, chain)
    text = {"json": render_json, "html": render_html, "csv": render_csv}[fmt](data)
    home = Path(os.environ.get("GUARDRAIL_HOME", Path.home() / ".guardrail"))
    target_dir = Path(out_dir) if out_dir else home / "reports"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"guardrail-report-{time.strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return target
