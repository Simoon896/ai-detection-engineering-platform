"""MCP-compatible server for controlled Atomic Red Team execution."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from atomic_mcp_server import __version__
from atomic_mcp_server.config import AtomicConfig, get_config
from atomic_mcp_server.executor import (
    ExecutionResult,
    create_executor,
    ps_quote,
    validate_technique,
    validate_test_number,
)
from atomic_mcp_server.ledger import RunLedger

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("atomic_mcp_server.audit")

MCP_PROTOCOL_VERSION = "2025-11-25"
WRITE_SCOPE_TOOLS = frozenset({
    "snapshot_create",
    "snapshot_revert",
    "install_prereqs",
    "run_atomic",
    "cleanup_atomic",
})


class MCPRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


class MCPResponse(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: str | int | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        data = super().model_dump(*args, **kwargs)
        if data.get("error") is not None:
            data.pop("result", None)
        else:
            data.pop("error", None)
        return data


@dataclass
class AuthToken:
    scopes: list[str]
    api_key_id: str = "authless"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class MCPSession:
    def __init__(self, auth_token: AuthToken | None = None) -> None:
        self._auth_token = auth_token


def _auth_token_from_env() -> AuthToken:
    allow_write = os.getenv("ATOMIC_AUTHLESS_ALLOW_WRITE", "false").lower() in {"1", "true", "yes"}
    scopes = ["atomic:read", "atomic:write"] if allow_write else ["atomic:read"]
    return AuthToken(scopes=scopes)


def _required_scope(tool_name: str) -> str:
    return "atomic:write" if tool_name in WRITE_SCOPE_TOOLS else "atomic:read"


def _result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _json_result(value: Any) -> dict[str, Any]:
    return _result(json.dumps(value, indent=2, sort_keys=True, default=str))


def _execution_to_dict(execution: ExecutionResult) -> dict[str, Any]:
    return {
        "command_executed": execution.command,
        "stdout": execution.stdout,
        "stderr": execution.stderr,
        "exit_code": execution.exit_code,
        "start_utc": execution.start_utc,
        "end_utc": execution.end_utc,
    }


def _run_host_powershell(script: str, config: AtomicConfig) -> ExecutionResult:
    from atomic_mcp_server.executor import utc_now

    if config.transport != "hyperv_direct":
        raise ValueError("Snapshot tools require ATOMIC_TRANSPORT=hyperv_direct")
    argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]
    start = utc_now()
    completed = subprocess.run(
        argv,
        capture_output=True,
        check=False,
        text=True,
        timeout=config.max_runtime_seconds,
    )
    end = utc_now()
    return ExecutionResult(
        command=" ".join(argv),
        stdout=completed.stdout[: config.output_limit_bytes],
        stderr=completed.stderr[: config.output_limit_bytes],
        exit_code=completed.returncode,
        start_utc=start,
        end_utc=end,
    )


async def handle_tools_list(params: dict[str, Any], session: MCPSession) -> dict[str, Any]:
    _ = params
    tools = [
        {
            "name": "vm_status",
            "description": "Read-only status check for the configured Atomic Red Team Windows test VM.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "list_atomics",
            "description": "List Atomic Red Team technique folders available on the test VM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string", "description": "Optional MITRE technique ID filter, e.g. T1059.001"}
                },
                "required": [],
            },
        },
        {
            "name": "get_atomic_details",
            "description": "Read atomic YAML details for one technique from the test VM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string", "description": "MITRE technique ID, e.g. T1059.001"},
                    "test_number": {"type": "integer", "minimum": 1, "maximum": 999},
                },
                "required": ["technique"],
            },
        },
        {
            "name": "check_prereqs",
            "description": "Run Invoke-AtomicTest -GetPrereqs for one test. Read-only check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "test_number": {"type": "integer", "minimum": 1, "maximum": 999},
                },
                "required": ["technique", "test_number"],
            },
        },
        {
            "name": "get_run_ledger",
            "description": "Read recent ART run records used to correlate with Wazuh alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
                "required": [],
            },
        },
        {
            "name": "snapshot_create",
            "description": "[WRITE] Create a Hyper-V checkpoint for the configured test VM before detonation.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Checkpoint name"}},
                "required": [],
            },
        },
        {
            "name": "snapshot_revert",
            "description": "[WRITE] Restore a Hyper-V checkpoint for the configured test VM after detonation.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Checkpoint name"}},
                "required": [],
            },
        },
        {
            "name": "install_prereqs",
            "description": "[WRITE] Run Invoke-AtomicTest -GetPrereqs for one atomic test on the VM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "test_number": {"type": "integer", "minimum": 1, "maximum": 999},
                },
                "required": ["technique", "test_number"],
            },
        },
        {
            "name": "run_atomic",
            "description": "[DETONATE][WRITE] Execute one Atomic Red Team PowerShell test on the isolated VM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "test_number": {"type": "integer", "minimum": 1, "maximum": 999},
                    "input_args": {"type": "object", "additionalProperties": True},
                },
                "required": ["technique", "test_number"],
            },
        },
        {
            "name": "cleanup_atomic",
            "description": "[WRITE] Run Invoke-AtomicTest -Cleanup for one atomic test on the VM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "test_number": {"type": "integer", "minimum": 1, "maximum": 999},
                },
                "required": ["technique", "test_number"],
            },
        },
    ]
    token = getattr(session, "_auth_token", None)
    if not token or not token.has_scope("atomic:write"):
        tools = [tool for tool in tools if tool["name"] not in WRITE_SCOPE_TOOLS]
    return {"tools": tools}


async def handle_tools_call(params: dict[str, Any], session: MCPSession) -> dict[str, Any]:
    tool_name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("Tool name is required")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")

    token = getattr(session, "_auth_token", None)
    required = _required_scope(tool_name)
    if not token or not token.has_scope(required):
        raise ValueError(f"Insufficient permissions: tool '{tool_name}' requires '{required}' scope")

    config = get_config()
    executor = create_executor(config)
    ledger = RunLedger(config.ledger_path)

    if tool_name in WRITE_SCOPE_TOOLS:
        audit_logger.warning("AUDIT: tool=%s target=%s args=%s", tool_name, config.allowed_target, arguments)

    try:
        if tool_name == "vm_status":
            execution = await executor.run_script("$PSVersionTable.PSVersion.ToString(); hostname")
            return _json_result({"target": config.allowed_target, "transport": config.transport, **_execution_to_dict(execution)})

        if tool_name == "list_atomics":
            technique = arguments.get("technique")
            filter_clause = ""
            if technique:
                filter_clause = f" -Filter {ps_quote(validate_technique(technique))}"
            script = f"Get-ChildItem -Directory{filter_clause} | Select-Object -ExpandProperty Name"
            execution = await executor.run_script(script)
            return _json_result(_execution_to_dict(execution))

        if tool_name == "get_atomic_details":
            technique = validate_technique(arguments.get("technique"))
            validate_test_number(arguments.get("test_number", 1))
            script = (
                f"$path = Join-Path (Get-Location) {ps_quote(technique)}; "
                f"Get-Content (Join-Path $path {ps_quote(technique + '.yaml')}) -Raw"
            )
            execution = await executor.run_script(script)
            return _json_result(_execution_to_dict(execution))

        if tool_name == "check_prereqs":
            execution = await executor.check_prereqs(arguments.get("technique"), arguments.get("test_number"))
            return _json_result(_execution_to_dict(execution))

        if tool_name == "get_run_ledger":
            limit = int(arguments.get("limit", 100))
            return _json_result({"records": ledger.read_all(limit=limit)})

        if tool_name == "snapshot_create":
            name = str(arguments.get("name") or config.snapshot_name)
            script = f"Checkpoint-VM -Name {ps_quote(config.vm_name)} -SnapshotName {ps_quote(name)}"
            return _json_result(_execution_to_dict(_run_host_powershell(script, config)))

        if tool_name == "snapshot_revert":
            name = str(arguments.get("name") or config.snapshot_name)
            script = (
                f"Restore-VMSnapshot -VMName {ps_quote(config.vm_name)} "
                f"-Name {ps_quote(name)} -Confirm:$false"
            )
            return _json_result(_execution_to_dict(_run_host_powershell(script, config)))

        if tool_name == "install_prereqs":
            execution = await executor.check_prereqs(arguments.get("technique"), arguments.get("test_number"))
            return _json_result(_execution_to_dict(execution))

        if tool_name == "run_atomic":
            technique = validate_technique(arguments.get("technique"))
            test_number = validate_test_number(arguments.get("test_number"))
            execution = await executor.run_atomic(technique, test_number, arguments.get("input_args"))
            record = {
                "technique": technique,
                "test_number": test_number,
                "agent": config.windows_agent_name,
                **_execution_to_dict(execution),
            }
            persisted = ledger.append(record)
            return _json_result({"run": persisted})

        if tool_name == "cleanup_atomic":
            execution = await executor.cleanup_atomic(arguments.get("technique"), arguments.get("test_number"))
            return _json_result(_execution_to_dict(execution))

        raise ValueError(f"Unknown tool: {tool_name}")
    except Exception as exc:
        logger.exception("Atomic tool failed: %s", tool_name)
        return _error(str(exc))


app = FastAPI(title="Atomic Red Team MCP Server", version=__version__)


@app.get("/health")
async def health() -> dict[str, Any]:
    config = get_config()
    return {
        "status": "healthy",
        "service": "atomic-mcp-server",
        "version": __version__,
        "transport": config.transport,
        "target": config.allowed_target,
    }


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
        mcp_request = MCPRequest(**payload)
        session = MCPSession(auth_token=_auth_token_from_env())
        params = mcp_request.params or {}
        if mcp_request.method == "initialize":
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atomic-redteam-mcp", "version": __version__},
            }
        elif mcp_request.method == "tools/list":
            result = await handle_tools_list(params, session)
        elif mcp_request.method == "tools/call":
            result = await handle_tools_call(params, session)
        elif mcp_request.method == "ping":
            result = {}
        else:
            raise ValueError(f"Method not supported: {mcp_request.method}")
        return MCPResponse(id=mcp_request.id, result=result).model_dump()
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        logger.exception("MCP request failed")
        return MCPResponse(id=None, error={"code": -32603, "message": str(exc)}).model_dump()
