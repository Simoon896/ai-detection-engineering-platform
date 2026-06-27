#!/usr/bin/env python3
"""Run a batch of ART tests via Atomic MCP and correlate Wazuh alerts."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

ATOMIC_URL = os.getenv("ATOMIC_MCP_URL", "http://127.0.0.1:3001/mcp")
WAZUH_URL = os.getenv("WAZUH_MCP_URL", "http://127.0.0.1:3000/mcp")
AGENT_ID = "004"
INTERVAL_SEC = int(os.getenv("ART_INTERVAL_SEC", "10"))
ALERT_WAIT_SEC = int(os.getenv("ART_ALERT_WAIT_SEC", "15"))

TESTS = [
    ("T1547.009", 1, "Shortcut modification persistence"),
    ("T1053.005", 2, "Scheduled task (ONLOGON)"),
    ("T1218.011", 1, "Rundll32 execution"),
    ("T1047", 1, "WMI process create"),
    ("T1562.001", 1, "Disable Windows Defender (tamper)"),
]


def mcp_call(url: str, tool: str, arguments: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as resp:
        body = json.loads(resp.read().decode())
    if "error" in body and body["error"]:
        raise RuntimeError(body["error"])
    result = body.get("result", {})
    if result.get("isError"):
        text = result.get("content", [{}])[0].get("text", "unknown error")
        raise RuntimeError(text)
    text = result.get("content", [{}])[0].get("text", "{}")
    return json.loads(text) if text.strip().startswith("{") else {"raw": text}


def fetch_high_alerts(start_utc: str) -> list[dict]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_wazuh_alerts",
            "arguments": {
                "agent_id": AGENT_ID,
                "level": "10+",
                "timestamp_start": start_utc,
                "limit": 50,
                "compact": True,
            },
        },
    }
    req = urllib.request.Request(
        WAZUH_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode())
    text = body.get("result", {}).get("content", [{}])[0].get("text", "{}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    items = data.get("data", {}).get("affected_items", [])
    return items if isinstance(items, list) else []


def summarize_alerts(alerts: list[dict]) -> list[str]:
    lines = []
    seen = set()
    for a in alerts:
        rule = a.get("rule", {})
        rid = rule.get("id", "?")
        level = rule.get("level", "?")
        desc = (rule.get("description") or "")[:80]
        key = (rid, level, desc)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"rule {rid} L{level}: {desc}")
    return lines


def main() -> int:
    results = []
    for idx, (technique, test_num, label) in enumerate(TESTS):
        if idx > 0:
            print(f"\n--- waiting {INTERVAL_SEC}s before next test ---")
            time.sleep(INTERVAL_SEC)

        start_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"\n=== Test {idx + 1}/5: {technique} test {test_num} — {label} ===")
        print(f"start_utc={start_utc}")

        try:
            run = mcp_call(ATOMIC_URL, "run_atomic", {"technique": technique, "test_number": test_num})
            run_data = run.get("run", run)
            print(
                f"run_atomic: exit={run_data.get('exit_code')} run_id={run_data.get('run_id')}"
            )
            if run_data.get("stderr"):
                print(f"stderr: {str(run_data.get('stderr'))[:200]}")
        except Exception as exc:
            print(f"run_atomic FAILED: {exc}")
            results.append(
                {
                    "technique": technique,
                    "test": test_num,
                    "label": label,
                    "exit_code": None,
                    "run_id": None,
                    "detected": False,
                    "alerts": [],
                    "error": str(exc),
                }
            )
            continue

        print(f"waiting {ALERT_WAIT_SEC}s for alert indexing...")
        time.sleep(ALERT_WAIT_SEC)

        alerts = fetch_high_alerts(start_utc)
        alert_lines = summarize_alerts(alerts)
        detected = len(alert_lines) > 0
        print(f"high alerts (L10+): {len(alert_lines)}")
        for line in alert_lines[:8]:
            print(f"  - {line}")

        try:
            cleanup = mcp_call(
                ATOMIC_URL,
                "cleanup_atomic",
                {"technique": technique, "test_number": test_num},
            )
            print(f"cleanup: exit={cleanup.get('exit_code', '?')}")
        except Exception as exc:
            print(f"cleanup FAILED: {exc}")

        results.append(
            {
                "technique": technique,
                "test": test_num,
                "label": label,
                "exit_code": run_data.get("exit_code"),
                "run_id": run_data.get("run_id"),
                "detected": detected,
                "alerts": alert_lines,
                "error": None,
            }
        )

    print("\n=== BATCH SUMMARY ===")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
