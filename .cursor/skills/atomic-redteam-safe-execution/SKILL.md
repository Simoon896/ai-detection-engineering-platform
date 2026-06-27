---
name: atomic-redteam-safe-execution
description: Safely execute Atomic Red Team tests on the allowlisted Windows VM via atomic-redteam MCP only, with per-phase user approval, ART-only tests, mandatory cleanup, and handoff to Wazuh detection engineers. Use when detonating ART tests, running run_atomic, red team validation, or detection coverage testing.
---

# Atomic Red Team Safe Execution

## Scope

- MCP server: `atomic-redteam` (`http://127.0.0.1:3001/mcp`)
- Target: single VM in `.env.atomic.local` (`ATOMIC_TARGET_HOST`)
- Wazuh agent name: `ATOMIC_WAZUH_AGENT_NAME` (currently `windowsTest`)
- Full playbook: [docs/atomic-redteam-safety.md](../../../docs/atomic-redteam-safety.md)

## Iron rules

1. **ART only** — Use `Invoke-AtomicTest` indirectly via MCP `run_atomic`. Never craft attack commands.
2. **MCP only** — No direct WinRM, SSH, or local PowerShell on the VM from the agent.
3. **One test at a time** — Single `technique` + `test_number` per approved detonation.
4. **Approve every phase** — Stop and ask the user before each gated step (see workflow).
5. **Always cleanup** — `cleanup_atomic` after handoff, even if the test failed or alerts were empty.
6. **Never allowlisted** — Do not assume `run_atomic` / `cleanup_atomic` auto-run; user must approve in Cursor.

## Workflow

Copy and track:

```
- [ ] Phase 0: Preflight (read-only)
- [ ] Phase 1: Select test (ART catalog only)
- [ ] Phase 2: Prereqs
- [ ] Phase 3: Install prereqs (if needed)
- [ ] Phase 4: Detonate (run_atomic)
- [ ] Phase 5: Handoff
- [ ] Phase 6: Cleanup
- [ ] Phase 7: User summary
```

### Phase 0 — Preflight (read-only)

Tools: `vm_status`, optionally `get_run_ledger`

Report: transport, target, hostname, PS version, agent name.

**Ask:** "Preflight OK. Proceed to technique selection?"

### Phase 1 — Select test (ART catalog only)

Tools: `list_atomics`, `get_atomic_details`

- User must pick or confirm technique + test number from ART YAML.
- Reject unknown IDs or tests not in `get_atomic_details`.
- Check [tools/redteam/DESTRUCTIVE_TECHNIQUES.md](../../../tools/redteam/DESTRUCTIVE_TECHNIQUES.md); flag high-risk tests.

**Ask:** "Run prereq check for Txxxx test N?"

### Phase 2 — Prereqs (read-only)

Tool: `check_prereqs`

Summarize missing prereqs without installing yet.

**Ask:** "Install prereqs?" only if something is missing.

### Phase 3 — Install prereqs (gated)

Tool: `install_prereqs` — only after approval.

### Phase 4 — Detonate (gated)

Tool: `run_atomic` — only after approval.

Record: `run_id`, `start_utc`, `end_utc`, `exit_code`, brief stdout summary (no secrets).

### Phase 5 — Handoff

Fill [tools/redteam/HANDOFF_TEMPLATE.md](../../../tools/redteam/HANDOFF_TEMPLATE.md) for the Wazuh detection engineer.

Tell the user and detection agent:

- Ledger row is in `tools/redteam/ledger.jsonl`
- Query window and `agent.name` for `search_alerts`

**Do not** tune Wazuh rules in this skill.

**Ask:** "Handoff complete. Run cleanup_atomic for Txxxx test N?"

### Phase 6 — Cleanup (gated, mandatory)

Tool: `cleanup_atomic` — always after handoff.

Verify exit code; note residual artifacts in handoff if cleanup failed.

### Phase 7 — User summary

Short report: what ran, handoff status, cleanup status, next step (detection correlation).

## Collaboration

After Phase 5, the Wazuh detection engineer uses skill `wazuh-art-detection-handoff` with the ledger row. You do not edit `coverage.md` unless the user asks you to act as both roles.

## Abort

If the user declines any phase, stop. If detonation ran but handoff incomplete, still offer cleanup before ending.
