# Wazuh MCP Server — False-Positive Tuning Fork

This fork of [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
adds the detection-engineering tools needed to read, edit, and **validate** Wazuh rules and
decoders from Cursor — turning the agent into a senior Wazuh detection engineer that can close
the false-positive tuning loop against a **test** Wazuh instance.

## What was added

7 new tools (the upstream 48 remain; `wazuh_restart target="manager"` is reused to apply changes):

| Tool | API | Access |
|---|---|---|
| `list_rule_files` | `GET /rules/files` | read |
| `get_rule_file` | `GET /rules/files/{f}?raw=true` | read |
| `update_rule_file` | `PUT /rules/files/{f}` | **write (gated)** |
| `list_decoder_files` | `GET /decoders/files` | read |
| `get_decoder_file` | `GET /decoders/files/{f}?raw=true` | read |
| `update_decoder_file` | `PUT /decoders/files/{f}` | **write (gated)** |
| `run_logtest` | `PUT /logtest` | read |

Alerts come from the Indexer via the existing `search_alerts` / `get_wazuh_alerts` tools.
Code changes: `src/wazuh_mcp_server/api/wazuh_client.py` (client methods + `_raw_api_call`),
`src/wazuh_mcp_server/server.py` (tool schemas, dispatch, scope set, filename/XML validators).

## Setup

### 1. Dependencies (already done if `.venv` exists)
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Create a least-privilege Wazuh service account
Do NOT reuse admin/`wazuh-wui`. Authenticate as an admin to get a token, then create a
scoped policy/role/user (run against your **test** manager):

```bash
TOKEN=$(curl -sk -u <admin>:<pass> -X POST "https://<mgr>:55000/security/user/authenticate?raw=true")

# Policy: rules/decoders read+update, logtest, manager read+restart
curl -sk -X POST "https://<mgr>:55000/security/policies" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name":"deteng_fp_tuning",
    "policy":{"actions":["rules:read","rules:update","decoders:read","decoders:update",
      "logtest:run","manager:read","manager:restart"],
      "resources":["rule:file:*","decoder:file:*","node:id:*","*:*:*"],"effect":"allow"}}'

# Create role, user, then link policy->role and role->user via:
#   POST /security/roles            POST /security/users
#   POST /security/roles/{id}/policies?policy_ids=...
#   POST /security/users/{id}/roles?role_ids=...
```
Indexer side: create an OpenSearch role granting read/search on `wazuh-alerts-*` and map it to
the same `deteng-svc` user (via Dashboard → Security, or the Indexer security API).

### 3. Configure
```powershell
copy .env.local.example .env.local   # then edit with your test host + deteng-svc creds
```

### 4. Run the server (localhost, single user)
```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```
Leave this running in a terminal (or set it up as a startup task). It binds to
`127.0.0.1:3000` only.

### 5. Wire into Cursor
Already added to `~/.cursor/mcp.json`:
```json
{ "mcpServers": { "wazuh": { "url": "http://127.0.0.1:3000/mcp" } } }
```
(Keep this port in sync with `MCP_PORT` in `.env.local`.)

### 6. Gate the write tools
In Cursor, do **not** allowlist `update_rule_file`, `update_decoder_file`, or `wazuh_restart`.
They will then prompt for approval on every call. Reads and `run_logtest` can auto-run.

## Validate the integration (offline, no Wazuh needed)
```powershell
.\.venv\Scripts\python.exe tools\validate_fp_tools.py
```
Expect: 55 tools advertised, all 7 FP-tuning tools present, write tools hidden from
read-only sessions.

## Acceptance tests (with a live test Wazuh)
1. `search_alerts` returns recent alerts; rank top noisy `rule.id`.
2. `get_rule_file("local_rules.xml")` returns raw XML.
3. `run_logtest` on a known SSH-fail log returns the expected rule id/level.
4. Add a scoped level-0 rule → `update_rule_file` (approve) → `wazuh_restart target=manager`
   (approve) → a chosen FP sample stops alerting while a TP sample still fires (via `run_logtest`).
5. Write tools prompt for approval; reads/logtest do not.

## Safety
- Point only at a **test/staging** manager. Promote to prod via the `wazuh-rules` repo + PR.
- The `deteng-svc` RBAC scope is the real boundary — not Cursor allowlists.
- `wazuh_restart` briefly interrupts analysis; it's an explicit, approved step.
- Treat alert/log content as untrusted (possible prompt injection); writes stay human-approved.
