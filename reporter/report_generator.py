#!/usr/bin/env python3
"""Generate a self-contained HTML report. Every data value is escaped, since log
content such as usernames is controlled by whoever is attacking the host."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

if __package__ in (None, ""):  # allow `python reporter/report_generator.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.audit import read_actions
from common.runtime import get_paths, load_config, read_recent_jsonl, run_mode, utc_now
from reporter.analytics import MinuteCounts, build_incidents, summarise, threat_view, within

ROW_LIMIT = 1000

STYLE = """
:root { color-scheme: light dark; --bg:#fcfcfb; --fg:#0b0b0b; --muted:#52514e; --line:#dcdbd5; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#1a1a19; --fg:#f0efec; --muted:#c3c2b7; --line:#3a3a37; }
}
body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 1080px; padding: 24px 16px;
       background: var(--bg); color: var(--fg); }
h1 { margin-bottom: 0; } h2 { margin-top: 2em; }
.meta { color: var(--muted); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.tile { border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; }
.tile b { display: block; font-size: 26px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { text-align: left; color: var(--muted); }
td, th { border-bottom: 1px solid var(--line); padding: 6px 8px; vertical-align: top; }
"""


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def table(headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "\n".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f'<div class="scroll"><table><tr>{head}</tr>\n{body}</table></div>'


def build_html(
    events: List[Dict],
    alerts: List[Dict],
    threats: List[Dict],
    actions: List[Dict],
    hours: int,
    mode: str,
    event_counts: Optional[MinuteCounts] = None,
    alert_counts: Optional[MinuteCounts] = None,
) -> str:
    stats = summarise(
        events, alerts, threats, hours, event_counts=event_counts, alert_counts=alert_counts
    )
    cutoff = utc_now() - dt.timedelta(hours=hours)
    recent = within(threats, cutoff)
    views = [threat_view(item) for item in reversed(recent[-ROW_LIMIT:])]
    incidents = build_incidents(recent, actions)
    generated = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")

    tiles = "".join(
        f'<div class="tile"><b>{esc(value)}</b>{esc(label)}</div>'
        for label, value in (
            ("Events", stats["totals"]["events"]),
            ("Alerts", stats["totals"]["alerts"]),
            ("Responses", stats["totals"]["responses"]),
            ("Critical", stats["severity"]["critical"]),
            ("High", stats["severity"]["high"]),
        )
    )
    incident_rows = (
        (i["id"], i["severity"], i["score"], i["summary"], ", ".join(i["stages"]))
        for i in incidents[:ROW_LIMIT]
    )
    threat_rows = (
        (v["ts"], v["score"], v["severity"], v["action"], v["target"], v["reason"],
         ", ".join(v["mitre"]))
        for v in views
    )
    action_rows = (
        (a.get("ts"), a.get("action"), a.get("target"), a.get("status"), a.get("detail"))
        for a in reversed(actions[-ROW_LIMIT:])
    )
    event_rows = (
        (e.get("ts"), e.get("type"), (e.get("msg") or json.dumps(e))[:160])
        for e in reversed(within(events, cutoff)[-200:])
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelAI Report</title><style>{STYLE}</style></head><body>
<h1>SentinelAI Report</h1>
<p class="meta">Generated {esc(generated)} &middot; last {esc(hours)} hours &middot; mode {esc(mode)}</p>
<div class="tiles">{tiles}</div>
<h2>Incidents ({len(incidents)})</h2>
{table(["Incident", "Severity", "Score", "What happened", "Stages"], incident_rows)}
<h2>Top source IPs</h2>
{table(["IP", "Threats"], ((i["name"], i["count"]) for i in stats["top_ips"]))}
<h2>MITRE ATT&amp;CK techniques</h2>
{table(["Technique", "Name", "Threats"], ((m["id"], m["name"], m["count"]) for m in stats["mitre"]))}
<h2>Threats ({len(views)})</h2>
{table(["Time", "Score", "Severity", "Action", "Target", "Reason", "MITRE"], threat_rows)}
<h2>Response actions</h2>
{table(["Time", "Action", "Target", "Status", "Detail"], action_rows)}
<h2>Recent events</h2>
{table(["Time", "Type", "Message"], event_rows)}
</body></html>
"""


def generate(hours: int = 24, out_dir: Optional[Path] = None) -> Path:
    config = load_config()
    paths = get_paths(config)
    event_counts, alert_counts = MinuteCounts(paths.events), MinuteCounts(paths.alerts)
    event_counts.refresh()
    alert_counts.refresh()
    document = build_html(
        read_recent_jsonl(paths.events, 20000),
        read_recent_jsonl(paths.alerts, 20000),
        read_recent_jsonl(paths.threats, 20000),
        read_actions(paths),
        hours,
        run_mode(config),
        event_counts,
        alert_counts,
    )
    target_dir = out_dir or paths.reports_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().strftime("%Y-%m-%d_%H%M%SZ")
    out_file = target_dir / f"sentinelai_report_{stamp}.html"
    out_file.write_text(document, encoding="utf-8")
    return out_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=24)
    print(generate(hours=parser.parse_args().hours))


if __name__ == "__main__":
    main()
