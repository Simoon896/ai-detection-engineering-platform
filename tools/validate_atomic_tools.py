"""Offline validation for the Atomic Red Team MCP server tools.

Runs without a Windows VM: it only inspects tools/list and local validation logic.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from atomic_mcp_server.config import AtomicConfig  # noqa: E402
from atomic_mcp_server.executor import HyperVDirectExecutor  # noqa: E402
from atomic_mcp_server.server import WRITE_SCOPE_TOOLS, handle_tools_list  # noqa: E402

EXPECTED_READ = {
    "vm_status",
    "list_atomics",
    "get_atomic_details",
    "check_prereqs",
    "get_run_ledger",
}

EXPECTED_WRITE = {
    "snapshot_create",
    "snapshot_revert",
    "install_prereqs",
    "run_atomic",
    "cleanup_atomic",
}


class _WriteToken:
    def has_scope(self, _scope: str) -> bool:
        return True


class _WriteSession:
    _auth_token = _WriteToken()


class _ReadToken:
    def has_scope(self, scope: str) -> bool:
        return scope == "atomic:read"


class _ReadSession:
    _auth_token = _ReadToken()


async def _main() -> int:
    write_res = await handle_tools_list({}, _WriteSession())
    write_names = {tool["name"] for tool in write_res["tools"]}
    expected = EXPECTED_READ | EXPECTED_WRITE
    missing = expected - write_names
    print(f"Total tools advertised with atomic:write: {len(write_names)}")
    print(f"Atomic tools present: {sorted(expected & write_names)}")
    if missing:
        print(f"MISSING: {sorted(missing)}")
        return 1

    read_res = await handle_tools_list({}, _ReadSession())
    read_names = {tool["name"] for tool in read_res["tools"]}
    leaked = WRITE_SCOPE_TOOLS & read_names
    if leaked:
        print(f"WRITE TOOLS LEAKED to read-only session: {sorted(leaked)}")
        return 1

    config = AtomicConfig(allowed_target="windowsTest", transport="hyperv_direct")
    executor = HyperVDirectExecutor(config)
    try:
        executor.validate_target("prodServer")
    except ValueError:
        print("OK: non-allowlisted targets are rejected")
    else:
        print("ERROR: non-allowlisted target was accepted")
        return 1

    print("OK: write tools correctly hidden from read-only sessions")
    print("VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
