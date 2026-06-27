import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def test_atomic_config_defaults_to_localhost_and_safe_transport(monkeypatch):
    from atomic_mcp_server.config import AtomicConfig

    monkeypatch.delenv("ATOMIC_MCP_HOST", raising=False)
    monkeypatch.delenv("ATOMIC_MCP_PORT", raising=False)
    monkeypatch.delenv("ATOMIC_TRANSPORT", raising=False)
    monkeypatch.setenv("ATOMIC_TARGET_HOST", "windowsTest")

    config = AtomicConfig.from_env()

    assert config.mcp_host == "127.0.0.1"
    assert config.mcp_port == 3001
    assert config.transport == "hyperv_direct"
    assert config.allowed_target == "windowsTest"


def test_resolve_winrm_username_prefixes_local_account():
    from atomic_mcp_server.config import resolve_winrm_username

    assert resolve_winrm_username("atomic-runner") == r".\atomic-runner"
    assert resolve_winrm_username("atomic-runner", ".") == r".\atomic-runner"
    assert resolve_winrm_username("atomic-runner", "windows-test") == r"windows-test\atomic-runner"
    assert resolve_winrm_username(r".\atomic-runner") == r".\atomic-runner"


def test_atomic_config_winrm_auth_optional(monkeypatch):
    from atomic_mcp_server.config import AtomicConfig, winrm_auth_attempts

    monkeypatch.setenv("ATOMIC_TARGET_HOST", "192.0.2.145")
    monkeypatch.setenv("ATOMIC_TRANSPORT", "winrm")
    monkeypatch.delenv("ATOMIC_WINRM_AUTH", raising=False)

    config = AtomicConfig.from_env()

    assert config.winrm_auth is None
    assert winrm_auth_attempts(config) == ("negotiate", "ntlm")


def test_winrm_auth_attempts_honors_explicit_setting(monkeypatch):
    from atomic_mcp_server.config import AtomicConfig, winrm_auth_attempts

    monkeypatch.setenv("ATOMIC_TARGET_HOST", "192.0.2.145")
    monkeypatch.setenv("ATOMIC_WINRM_AUTH", "basic")

    config = AtomicConfig.from_env()

    assert winrm_auth_attempts(config) == ("basic",)


def test_atomic_config_rejects_unsupported_transport(monkeypatch):
    from atomic_mcp_server.config import AtomicConfig

    monkeypatch.setenv("ATOMIC_TRANSPORT", "rdp")
    monkeypatch.setenv("ATOMIC_TARGET_HOST", "windowsTest")

    with pytest.raises(ValueError, match="Unsupported ATOMIC_TRANSPORT"):
        AtomicConfig.from_env()


def test_executor_rejects_non_allowlisted_target():
    from atomic_mcp_server.config import AtomicConfig
    from atomic_mcp_server.executor import HyperVDirectExecutor

    config = AtomicConfig(allowed_target="windowsTest", transport="hyperv_direct")
    executor = HyperVDirectExecutor(config)

    with pytest.raises(ValueError, match="not allowlisted"):
        executor.validate_target("prodServer")


def test_hyperv_executor_builds_argv_without_shell_string():
    from atomic_mcp_server.config import AtomicConfig
    from atomic_mcp_server.executor import HyperVDirectExecutor

    config = AtomicConfig(allowed_target="windowsTest", transport="hyperv_direct")
    executor = HyperVDirectExecutor(config)

    argv = executor.build_argv("Get-ComputerInfo | Select-Object -First 1")

    assert argv[:3] == ["powershell.exe", "-NoProfile", "-NonInteractive"]
    assert "-Command" in argv
    assert "Invoke-Command" in argv[-1]
    assert "-VMName 'windowsTest'" in argv[-1]


@pytest.mark.asyncio
async def test_write_tools_hidden_for_read_only_session():
    from atomic_mcp_server.server import WRITE_SCOPE_TOOLS, handle_tools_list

    class ReadOnlyToken:
        def has_scope(self, scope: str) -> bool:
            return scope == "atomic:read"

    class Session:
        _auth_token = ReadOnlyToken()

    result = await handle_tools_list({}, Session())
    names = {tool["name"] for tool in result["tools"]}

    assert WRITE_SCOPE_TOOLS
    assert not (WRITE_SCOPE_TOOLS & names)
    assert {"vm_status", "list_atomics", "get_run_ledger"} <= names


@pytest.mark.asyncio
async def test_run_ledger_appends_jsonl_records(tmp_path):
    from atomic_mcp_server.ledger import RunLedger

    ledger = RunLedger(tmp_path / "ledger.jsonl")
    record = ledger.append(
        {
            "technique": "T1059.001",
            "test_number": 1,
            "agent": "windowsTest",
            "start_utc": "2026-06-09T22:00:00Z",
            "end_utc": "2026-06-09T22:00:05Z",
            "exit_code": 0,
        }
    )

    rows = ledger.read_all()
    raw = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").strip()

    assert record["run_id"]
    assert rows == [record]
    assert json.loads(raw)["technique"] == "T1059.001"
