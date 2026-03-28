"""Generate a self-contained HTML scan report with dark-theme styling."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict


def generate_html_report(data: Dict[str, Any], output_path: str) -> None:
    summary = data.get("summary", {})
    stats = data.get("stats", {})
    results = data.get("results", [])
    config = data.get("config", {})

    results_sorted = sorted(results, key=lambda x: x.get("scoring", {}).get("score", 0), reverse=True)

    sev_counts = summary.get("by_severity", {})
    critical = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)
    medium = sev_counts.get("medium", 0)
    low = sev_counts.get("low", 0)
    info = sev_counts.get("info", 0)

    findings_html = ""
    for i, r in enumerate(results_sorted, 1):
        sev = r.get("scoring", {}).get("severity", "info")
        score = r.get("scoring", {}).get("score", 0)
        cat = r.get("category", "")
        payload = r.get("payload", "")[:300].replace("<", "&lt;").replace(">", "&gt;")
        response = r.get("response", "")[:500].replace("<", "&lt;").replace(">", "&gt;")
        finding_list = r.get("analysis", {}).get("findings", [])
        remediation = r.get("scoring", {}).get("remediation", [])
        impact = r.get("scoring", {}).get("impact", "")

        sev_class = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(sev, "info")

        findings_items = "".join(f"<li>{f}</li>" for f in finding_list)
        remed_items = "".join(f"<li>{r}</li>" for r in remediation)

        findings_html += f"""
        <div class="finding {sev_class}">
            <div class="finding-header">
                <span class="badge {sev_class}">{sev.upper()}</span>
                <span class="score">{score}/10</span>
                <span class="category">{cat}</span>
                <span class="finding-num">#{i}</span>
            </div>
            <div class="finding-body">
                <div class="section">
                    <h4>Payload</h4>
                    <pre>{payload}</pre>
                </div>
                <div class="section">
                    <h4>Response</h4>
                    <pre>{response}</pre>
                </div>
                <div class="section">
                    <h4>Findings</h4>
                    <ul>{findings_items}</ul>
                </div>
                <div class="section">
                    <h4>Impact</h4>
                    <p>{impact}</p>
                </div>
                <div class="section">
                    <h4>Remediation</h4>
                    <ul>{remed_items}</ul>
                </div>
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PromptStrike Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a0a2e 0%, #0d1117 50%, #1a0000 100%); padding: 40px; border-radius: 16px; margin-bottom: 30px; border: 1px solid #2a1040; }}
        header h1 {{ font-size: 2.5em; background: linear-gradient(90deg, #ff4444, #ff0080); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        header p {{ color: #888; margin-top: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: #12121a; border: 1px solid #222; border-radius: 12px; padding: 20px; text-align: center; }}
        .stat-card .value {{ font-size: 2em; font-weight: 700; }}
        .stat-card .label {{ color: #888; font-size: 0.9em; margin-top: 4px; }}
        .severity-chart {{ display: flex; gap: 12px; margin-bottom: 30px; }}
        .sev-bar {{ flex: 1; background: #12121a; border-radius: 12px; padding: 16px; text-align: center; border: 1px solid #222; }}
        .sev-bar .count {{ font-size: 2em; font-weight: 700; }}
        .sev-bar.critical {{ border-color: #ff2222; }} .sev-bar.critical .count {{ color: #ff2222; }}
        .sev-bar.high {{ border-color: #ff6600; }} .sev-bar.high .count {{ color: #ff6600; }}
        .sev-bar.medium {{ border-color: #ffcc00; }} .sev-bar.medium .count {{ color: #ffcc00; }}
        .sev-bar.low {{ border-color: #4488ff; }} .sev-bar.low .count {{ color: #4488ff; }}
        .sev-bar.info {{ border-color: #666; }} .sev-bar.info .count {{ color: #666; }}
        .findings-section h2 {{ font-size: 1.5em; margin-bottom: 20px; color: #fff; }}
        .finding {{ background: #12121a; border-radius: 12px; margin-bottom: 16px; border: 1px solid #222; overflow: hidden; }}
        .finding.critical {{ border-left: 4px solid #ff2222; }}
        .finding.high {{ border-left: 4px solid #ff6600; }}
        .finding.medium {{ border-left: 4px solid #ffcc00; }}
        .finding.low {{ border-left: 4px solid #4488ff; }}
        .finding.info {{ border-left: 4px solid #666; }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 16px 20px; background: #1a1a25; }}
        .badge {{ padding: 4px 12px; border-radius: 6px; font-size: 0.8em; font-weight: 700; }}
        .badge.critical {{ background: #ff222233; color: #ff4444; }}
        .badge.high {{ background: #ff660033; color: #ff8800; }}
        .badge.medium {{ background: #ffcc0033; color: #ffdd44; }}
        .badge.low {{ background: #4488ff33; color: #66aaff; }}
        .badge.info {{ background: #66666633; color: #999; }}
        .score {{ font-weight: 700; color: #fff; }}
        .category {{ color: #888; }}
        .finding-num {{ margin-left: auto; color: #555; }}
        .finding-body {{ padding: 20px; }}
        .section {{ margin-bottom: 16px; }}
        .section h4 {{ color: #ff4444; margin-bottom: 8px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
        pre {{ background: #0d0d14; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-break: break-word; border: 1px solid #1a1a25; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 4px; color: #ccc; }}
        footer {{ text-align: center; padding: 30px; color: #555; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PromptStrike</h1>
            <p>AI Prompt Injection Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {config.get('target', {{}}).get('provider', '')} / {config.get('target', {{}}).get('model', '')}</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="value">{summary.get('total', 0)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color:#ff2222">{summary.get('max_score', 0)}/10</div>
                <div class="label">Max Score</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get('total_requests', 0)}</div>
                <div class="label">Requests Sent</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get('total_tokens', 0):,}</div>
                <div class="label">Tokens Used</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get('success_rate', 0)}%</div>
                <div class="label">Success Rate</div>
            </div>
        </div>

        <div class="severity-chart">
            <div class="sev-bar critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
            <div class="sev-bar high"><div class="count">{high}</div><div class="label">High</div></div>
            <div class="sev-bar medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
            <div class="sev-bar low"><div class="count">{low}</div><div class="label">Low</div></div>
            <div class="sev-bar info"><div class="count">{info}</div><div class="label">Info</div></div>
        </div>

        <div class="findings-section">
            <h2>Findings ({summary.get('total', 0)})</h2>
            {findings_html}
        </div>

        <footer>
            Generated by PromptStrike v1.0.0 - github.com/V3n0mSh3ll/promptstrike
        </footer>
    </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
