"""Generate a markdown-formatted scan report."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict


def generate_markdown_report(data: Dict[str, Any], output_path: str) -> None:
    summary = data.get("summary", {})
    stats = data.get("stats", {})
    profile = data.get("profile", {})
    results = sorted(data.get("results", []), key=lambda x: x.get("scoring", {}).get("score", 0), reverse=True)
    cfg = data.get("config", {})

    lines = []
    lines.append("# PromptStrike Advanced Report")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append(f"Target: {cfg.get('target', {}).get('provider', '')} / {cfg.get('target', {}).get('model', '')}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total findings: **{summary.get('total', 0)}**")
    lines.append(f"- Max score: **{summary.get('max_score', 0)}/10**")
    lines.append(f"- Exploitable findings: **{summary.get('exploitable_count', 0)}**")
    lines.append(f"- Requests sent: **{stats.get('total_requests', 0)}**")
    lines.append(f"- Success rate: **{stats.get('success_rate', 0)}%**")
    lines.append("")
    lines.append("## Target Profile")
    lines.append("")
    lines.append(f"- Safety posture: **{profile.get('safety_posture', 'unknown')}**")
    lines.append(f"- Refusal fingerprint: **{profile.get('fingerprint', 'unknown')}**")
    lines.append(f"- Refusal rate: **{profile.get('refusal_rate', 0)}**")
    hints = ", ".join(f"{name} ({count})" for name, count in profile.get("provider_hints", [])) or "None"
    lines.append(f"- Provider hints: {hints}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for idx, item in enumerate(results[:50], 1):
        analysis = item.get("analysis", {})
        scoring = item.get("scoring", {})
        lines.append(f"### {idx}. {scoring.get('severity', 'info').upper()} - {item.get('category', 'unknown')}")
        lines.append("")
        lines.append(f"- Score: **{scoring.get('score', 0)}/10**")
        lines.append(f"- Attack success: **{analysis.get('attack_success', 'none')}**")
        lines.append(f"- Confidence: **{analysis.get('overall_confidence', 0)}**")
        findings = analysis.get("findings", [])
        if findings:
            lines.append(f"- Findings: {'; '.join(findings[:5])}")
        evidence = analysis.get("evidence", [])
        if evidence:
            lines.append(f"- Evidence: {'; '.join(evidence[:5])}")
        lines.append("")
        lines.append("**Payload**")
        lines.append("")
        lines.append("```text")
        lines.append((item.get("payload", "") or "")[:500])
        lines.append("```")
        lines.append("")
        lines.append("**Response**")
        lines.append("")
        lines.append("```text")
        lines.append((item.get("response", "") or "")[:1000])
        lines.append("```")
        lines.append("")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
