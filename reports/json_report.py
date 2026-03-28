"""Generate a machine-readable JSON scan report."""
from __future__ import annotations

import json
import os
from typing import Any, Dict


def generate_json_report(data: Dict[str, Any], output_path: str) -> None:
    clean_data = {
        "scan_info": {
            "start_time": data.get("start_time"),
            "end_time": data.get("end_time"),
            "provider": data.get("config", {}).get("target", {}).get("provider"),
            "model": data.get("config", {}).get("target", {}).get("model"),
            "mode": data.get("config", {}).get("attack", {}).get("mode"),
        },
        "summary": data.get("summary", {}),
        "stats": data.get("stats", {}),
        "profile": data.get("profile", {}),
        "findings": [],
    }

    for r in data.get("results", []):
        finding = {
            "category": r.get("category"),
            "severity": r.get("scoring", {}).get("severity", "info"),
            "score": r.get("scoring", {}).get("score", 0),
            "payload": r.get("payload", "")[:500],
            "response": r.get("response", "")[:1000],
            "bypassed": r.get("analysis", {}).get("bypassed", False),
            "system_leaked": r.get("analysis", {}).get("system_prompt_leaked", False),
            "pii_found": r.get("analysis", {}).get("pii_found", []),
            "findings": r.get("analysis", {}).get("findings", []),
            "evidence": r.get("analysis", {}).get("evidence", []),
            "confidence": r.get("analysis", {}).get("overall_confidence", 0),
            "attack_success": r.get("analysis", {}).get("attack_success", "none"),
            "remediation": r.get("scoring", {}).get("remediation", []),
            "timestamp": r.get("timestamp"),
        }
        clean_data["findings"].append(finding)

    clean_data["findings"].sort(key=lambda x: x.get("score", 0), reverse=True)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_data, f, indent=2, ensure_ascii=False)
