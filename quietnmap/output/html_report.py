"""HTML report generator — produces a self-contained scan report."""

from __future__ import annotations

import html
import time
from pathlib import Path

from quietnmap.models import PortState, ScanSession

# Color mapping for port states
STATE_COLORS = {
    PortState.OPEN: "#22c55e",
    PortState.CLOSED: "#ef4444",
    PortState.FILTERED: "#eab308",
    PortState.OPEN_FILTERED: "#f59e0b",
    PortState.UNFILTERED: "#06b6d4",
}


def generate_html(session: ScanSession) -> str:
    """Generate a self-contained HTML report."""
    hosts_html = ""
    for host in session.hosts:
        if not host.is_up:
            continue

        ports_rows = ""
        for p in host.ports:
            if not p.is_open:
                continue
            color = STATE_COLORS.get(p.state, "#888")
            service = html.escape(str(p.service)) if p.service.name != "unknown" else ""
            banner = html.escape(p.service.banner[:80]) if p.service.banner else ""
            ports_rows += f"""
                <tr>
                    <td class="port">{p.port}/{p.protocol.value}</td>
                    <td><span class="state" style="color:{color}">{p.state.value}</span></td>
                    <td>{service}</td>
                    <td class="banner">{banner}</td>
                    <td class="time">{p.response_time_ms:.0f}ms</td>
                </tr>"""

        os_info = ""
        if host.best_os_guess:
            os_info = f'<span class="os-guess">OS: {html.escape(str(host.best_os_guess))}</span>'

        hosts_html += f"""
        <div class="host">
            <div class="host-header">
                <h2>{html.escape(host.ip)}</h2>
                {f'<span class="hostname">{html.escape(host.hostname)}</span>' if host.hostname else ''}
                {os_info}
                <span class="open-count">{len(host.open_ports)} open port(s)</span>
            </div>
            <table class="ports-table">
                <thead>
                    <tr>
                        <th>Port</th><th>State</th><th>Service</th><th>Banner</th><th>Response</th>
                    </tr>
                </thead>
                <tbody>{ports_rows}</tbody>
            </table>
        </div>"""

    report_time = time.strftime("%Y-%m-%d %H:%M:%S")
    duration = f"{session.duration:.2f}s"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuietNmap Scan Report — {report_time}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a; color: #e2e8f0;
            padding: 2rem; line-height: 1.6;
        }}
        .header {{
            text-align: center; margin-bottom: 2rem;
            border-bottom: 1px solid #334155; padding-bottom: 1.5rem;
        }}
        .header h1 {{ color: #38bdf8; font-size: 2rem; }}
        .header .subtitle {{ color: #94a3b8; font-size: 0.9rem; }}
        .summary {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem; margin-bottom: 2rem;
        }}
        .stat {{
            background: #1e293b; border-radius: 8px; padding: 1rem;
            text-align: center; border: 1px solid #334155;
        }}
        .stat .value {{ font-size: 1.8rem; font-weight: bold; color: #38bdf8; }}
        .stat .label {{ color: #94a3b8; font-size: 0.85rem; }}
        .host {{
            background: #1e293b; border-radius: 8px; margin-bottom: 1.5rem;
            border: 1px solid #334155; overflow: hidden;
        }}
        .host-header {{
            padding: 1rem 1.5rem; background: #1e293b;
            display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
        }}
        .host-header h2 {{ color: #f1f5f9; font-size: 1.1rem; }}
        .hostname {{ color: #94a3b8; }}
        .os-guess {{ color: #a78bfa; font-size: 0.85rem; }}
        .open-count {{
            margin-left: auto; background: #166534; color: #4ade80;
            padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem;
        }}
        .ports-table {{ width: 100%; border-collapse: collapse; }}
        .ports-table th {{
            text-align: left; padding: 0.6rem 1.5rem;
            background: #0f172a; color: #94a3b8; font-size: 0.8rem;
            text-transform: uppercase; letter-spacing: 0.05em;
        }}
        .ports-table td {{ padding: 0.5rem 1.5rem; border-top: 1px solid #1e293b; }}
        .ports-table tr:hover {{ background: #263548; }}
        .port {{ font-weight: 600; font-family: monospace; }}
        .state {{ font-weight: 600; }}
        .banner {{ color: #94a3b8; font-family: monospace; font-size: 0.85rem; }}
        .time {{ color: #64748b; font-size: 0.85rem; }}
        .footer {{ text-align: center; color: #475569; margin-top: 2rem; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>QuietNmap Scan Report</h1>
        <div class="subtitle">Generated {report_time} • Duration: {duration}</div>
    </div>
    <div class="summary">
        <div class="stat">
            <div class="value">{len(session.hosts)}</div>
            <div class="label">Hosts Scanned</div>
        </div>
        <div class="stat">
            <div class="value">{len(session.hosts_up)}</div>
            <div class="label">Hosts Up</div>
        </div>
        <div class="stat">
            <div class="value">{session.total_open_ports}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="stat">
            <div class="value">{duration}</div>
            <div class="label">Scan Duration</div>
        </div>
    </div>
    {hosts_html}
    <div class="footer">
        Generated by QuietNmap v{session.scanner_version} —
        <a href="https://github.com/ayush/quietnmap" style="color:#38bdf8">GitHub</a>
    </div>
</body>
</html>"""


def save_html(session: ScanSession, path: str | Path) -> Path:
    """Save scan results as HTML report."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_html(session), encoding="utf-8")
    return path
