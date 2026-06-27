"""Offline validation that the false-positive tuning tools are registered.

Runs without a live Wazuh connection: it only inspects the tools/list output.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wazuh_mcp_server.server import handle_tools_list  # noqa: E402

EXPECTED = {
    "list_rule_files",
    "get_rule_file",
    "update_rule_file",
    "list_decoder_files",
    "get_decoder_file",
    "update_decoder_file",
    "run_logtest",
}


class _Tok:
    def has_scope(self, _scope: str) -> bool:
        return True  # simulate a wazuh:write-scoped token


class _Session:
    _auth_token = _Tok()


async def _main() -> int:
    res = await handle_tools_list({}, _Session())
    names = {t["name"] for t in res["tools"]}
    missing = EXPECTED - names
    print(f"Total tools advertised: {len(names)}")
    print(f"FP-tuning tools present: {sorted(EXPECTED & names)}")
    if missing:
        print(f"MISSING: {sorted(missing)}")
        return 1
    # Confirm write tools are scope-gated out for a read-only session
    class _RoTok:
        def has_scope(self, scope: str) -> bool:
            return scope == "wazuh:read"

    class _RoSession:
        _auth_token = _RoTok()

    ro = await handle_tools_list({}, _RoSession())
    ro_names = {t["name"] for t in ro["tools"]}
    leaked = {"update_rule_file", "update_decoder_file"} & ro_names
    if leaked:
        print(f"WRITE TOOLS LEAKED to read-only session: {sorted(leaked)}")
        return 1
    print("OK: write tools correctly hidden from read-only sessions")
    print("VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
