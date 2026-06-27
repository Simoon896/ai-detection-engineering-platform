# Agent Roles — Wazuh + Atomic Red Team

**Start here after a break:** [docs/ART-WAZUH-SESSION-GUIDE.md](docs/ART-WAZUH-SESSION-GUIDE.md) — full session summary, reboot checklist, and run-again steps.

This repo supports two cooperating Cursor agents via localhost MCP servers.

## Red Team Operator

- **Server:** `atomic-redteam` (`http://127.0.0.1:3001/mcp`)
- **Skill:** `atomic-redteam-safe-execution`
- **Rule:** `atomic-redteam-operator`
- **Docs:** [docs/atomic-redteam-safety.md](docs/atomic-redteam-safety.md)

Runs ART tests only through MCP, with per-phase user approval and mandatory cleanup.

## Wazuh Detection Engineer

- **Server:** `wazuh` (`http://127.0.0.1:3000/mcp`)
- **Skill:** `wazuh-art-detection-handoff`
- **Rule:** `wazuh-art-detection-loop`
- **Docs:** [FP_TUNING.md](FP_TUNING.md)

Correlates ledger runs with alerts; tunes rules only with user approval.

## Shared artifacts

| File | Purpose |
|------|---------|
| `tools/redteam/ledger.jsonl` | Append-only run records |
| `tools/redteam/HANDOFF_TEMPLATE.md` | Operator → detection handoff |
| `tools/redteam/coverage.md` | Technique detection status |
| `tools/redteam/SAFETY_CHECKLIST.md` | Per-run checklist |
| `tools/redteam/DESTRUCTIVE_TECHNIQUES.md` | High-risk technique policy |

## MCP allowlist

Never allowlist: `run_atomic`, `cleanup_atomic`, `install_prereqs`, `update_rule_file`, `wazuh_restart`.
