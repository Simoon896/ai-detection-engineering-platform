# Atomic Red Team MCP + Wazuh Detection Loop

> **Master guide (setup, reboot, checklist):** [ART-WAZUH-SESSION-GUIDE.md](ART-WAZUH-SESSION-GUIDE.md)

This repository now has two localhost MCP servers that can be used from one Cursor session:

- `wazuh` at `http://127.0.0.1:3000/mcp` for Wazuh alert search, logtest, rule reads, rule writes, and manager restart.
- `atomic-redteam` at `http://127.0.0.1:3001/mcp` for controlled Atomic Red Team execution on one allowlisted Windows test VM.

## Cursor MCP Wiring

Add the second server beside the existing Wazuh entry:

```json
{
  "mcpServers": {
    "wazuh": { "url": "http://127.0.0.1:3000/mcp" },
    "atomic-redteam": { "url": "http://127.0.0.1:3001/mcp" }
  }
}
```

Do not allowlist these tools:

- `run_atomic`
- `snapshot_create`
- `snapshot_revert`
- `install_prereqs`
- `cleanup_atomic`
- `update_rule_file`
- `update_decoder_file`
- `wazuh_restart`

This keeps every detonation, snapshot change, and ruleset write behind explicit approval.

By default, `.env.atomic.example` sets `ATOMIC_AUTHLESS_ALLOW_WRITE=false`, which hides the detonation and snapshot tools entirely. When you are ready to run live tests, set `ATOMIC_AUTHLESS_ALLOW_WRITE=true` in `.env.atomic.local` so Cursor can see those tools, but keep them off the allowlist so each call prompts for approval.

## VM Preparation

Prepare one isolated Windows VM that reports to Wazuh as `windowsTest`:

1. Place the VM on a host-only or isolated lab network.
2. Confirm the Wazuh agent is active and logs under `agent.name=windowsTest`.
3. Enable Sysmon and PowerShell 4103/4104 logging so Atomic Red Team PowerShell activity produces telemetry.
4. Install Atomic Red Team and Invoke-AtomicRedTeam inside the VM.
5. Create a clean snapshot named `atomic-clean`.
6. Choose the executor:
   - `hyperv_direct`: recommended for a local Hyper-V guest. No guest network listener is needed.
   - `winrm`: use WinRM over HTTPS on an isolated network with a least-privilege local account.

Copy `.env.atomic.example` to `.env.atomic.local`, fill in the target values, then start:

```powershell
powershell -ExecutionPolicy Bypass -File .\run-atomic.ps1
```

## Interactive Workflow

1. Use `vm_status` and `check_prereqs` from `atomic-redteam`.
2. Approve `snapshot_create`.
3. Approve `run_atomic` for one safe technique, for example `T1059.001` test `1`.
4. Use the returned `start_utc`, `end_utc`, and `agent` fields with Wazuh `search_alerts`.
5. If Wazuh misses or misclassifies the behavior, use `get_rule_file`, `run_logtest`, and gated rule updates through the Wazuh MCP server.
6. Approve `cleanup_atomic` and `snapshot_revert`.
7. Re-run the same atomic and update `tools/redteam/coverage.md`.

Run records are appended to `tools/redteam/ledger.jsonl`. The Wazuh detection-engineer agent should use those records as the source of truth for alert query windows.

## Safety framework

Before detonations, read:

- [atomic-redteam-safety.md](atomic-redteam-safety.md) — full playbook
- [AGENTS.md](../AGENTS.md) — operator vs detection engineer roles
- [tools/redteam/SAFETY_CHECKLIST.md](../tools/redteam/SAFETY_CHECKLIST.md) — per-run checklist
- [tools/redteam/DESTRUCTIVE_TECHNIQUES.md](../tools/redteam/DESTRUCTIVE_TECHNIQUES.md) — high-risk tests

Cursor project assets:

- Rules: `.cursor/rules/atomic-redteam-operator.mdc`, `.cursor/rules/wazuh-art-detection-loop.mdc`
- Skills: `.cursor/skills/atomic-redteam-safe-execution/`, `.cursor/skills/wazuh-art-detection-handoff/`

Wazuh agent name for correlation: `windowsTest`.
