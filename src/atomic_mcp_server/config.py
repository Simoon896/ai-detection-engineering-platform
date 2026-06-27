"""Configuration for the Atomic Red Team MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_TRANSPORTS = frozenset({"hyperv_direct", "winrm"})
SUPPORTED_WINRM_AUTH = frozenset({"basic", "ntlm", "negotiate", "credssp"})
DEFAULT_WINRM_AUTH_ATTEMPTS = ("negotiate", "ntlm")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AtomicConfig:
    """Runtime settings for controlling one isolated Windows ART test VM."""

    allowed_target: str
    transport: str = "hyperv_direct"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 3001
    windows_agent_name: str = "windowsTest"
    vm_name: str = "windowsTest"
    snapshot_name: str = "atomic-clean"
    atomics_path: str = r"C:\AtomicRedTeam\atomics"
    max_runtime_seconds: int = 600
    output_limit_bytes: int = 128_000
    ledger_path: Path = Path("tools/redteam/ledger.jsonl")
    coverage_path: Path = Path("tools/redteam/coverage.md")
    winrm_username: str | None = None
    winrm_password: str | None = None
    winrm_port: int = 5986
    winrm_verify_tls: bool = True
    winrm_auth: str | None = None
    winrm_domain: str | None = None

    def __post_init__(self) -> None:
        if not self.allowed_target or not self.allowed_target.strip():
            raise ValueError("ATOMIC_TARGET_HOST must identify the single allowlisted test VM")
        if self.transport not in SUPPORTED_TRANSPORTS:
            allowed = ", ".join(sorted(SUPPORTED_TRANSPORTS))
            raise ValueError(f"Unsupported ATOMIC_TRANSPORT '{self.transport}'. Expected one of: {allowed}")
        if self.max_runtime_seconds < 1 or self.max_runtime_seconds > 3600:
            raise ValueError("ATOMIC_MAX_RUNTIME_SECONDS must be between 1 and 3600")
        if self.output_limit_bytes < 1024 or self.output_limit_bytes > 5_000_000:
            raise ValueError("ATOMIC_OUTPUT_LIMIT_BYTES must be between 1024 and 5000000")
        if self.mcp_host != "127.0.0.1":
            raise ValueError("Atomic MCP server must bind to 127.0.0.1")
        if self.winrm_auth is not None and self.winrm_auth not in SUPPORTED_WINRM_AUTH:
            allowed = ", ".join(sorted(SUPPORTED_WINRM_AUTH))
            raise ValueError(f"Unsupported ATOMIC_WINRM_AUTH '{self.winrm_auth}'. Expected one of: {allowed}")

    @classmethod
    def from_env(cls) -> "AtomicConfig":
        """Build configuration from environment variables."""

        target = os.getenv("ATOMIC_TARGET_HOST", "windowsTest").strip()
        return cls(
            allowed_target=target,
            transport=os.getenv("ATOMIC_TRANSPORT", "hyperv_direct").strip().lower(),
            mcp_host=os.getenv("ATOMIC_MCP_HOST", "127.0.0.1").strip(),
            mcp_port=int(os.getenv("ATOMIC_MCP_PORT", "3001")),
            windows_agent_name=os.getenv("ATOMIC_WAZUH_AGENT_NAME", "windowsTest").strip(),
            vm_name=os.getenv("ATOMIC_VM_NAME", target).strip(),
            snapshot_name=os.getenv("ATOMIC_SNAPSHOT_NAME", "atomic-clean").strip(),
            atomics_path=os.getenv("ATOMIC_ATOMICS_PATH", r"C:\AtomicRedTeam\atomics").strip(),
            max_runtime_seconds=int(os.getenv("ATOMIC_MAX_RUNTIME_SECONDS", "600")),
            output_limit_bytes=int(os.getenv("ATOMIC_OUTPUT_LIMIT_BYTES", "128000")),
            ledger_path=Path(os.getenv("ATOMIC_LEDGER_PATH", "tools/redteam/ledger.jsonl")),
            coverage_path=Path(os.getenv("ATOMIC_COVERAGE_PATH", "tools/redteam/coverage.md")),
            winrm_username=os.getenv("ATOMIC_WINRM_USERNAME") or None,
            winrm_password=os.getenv("ATOMIC_WINRM_PASSWORD") or None,
            winrm_port=int(os.getenv("ATOMIC_WINRM_PORT", "5986")),
            winrm_verify_tls=_env_bool("ATOMIC_WINRM_VERIFY_TLS", True),
            winrm_auth=_optional_env("ATOMIC_WINRM_AUTH"),
            winrm_domain=(os.getenv("ATOMIC_WINRM_DOMAIN") or None),
        )


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    stripped = value.strip().lower()
    return stripped or None


def winrm_auth_attempts(config: AtomicConfig) -> tuple[str, ...]:
    """Return explicit auth mode or the default negotiation order."""

    if config.winrm_auth:
        return (config.winrm_auth,)
    return DEFAULT_WINRM_AUTH_ATTEMPTS


def resolve_winrm_username(username: str, domain: str | None = None) -> str:
    """Return a WinRM principal that targets a local account, not MicrosoftAccount."""

    clean = username.strip()
    if not clean:
        raise ValueError("ATOMIC_WINRM_USERNAME must not be empty")
    if "\\" in clean or "@" in clean or "%" in clean:
        return clean
    prefix = (domain or ".").strip()
    if not prefix:
        prefix = "."
    if not prefix.endswith("\\"):
        prefix = f"{prefix}\\"
    return f"{prefix}{clean}"


def get_config() -> AtomicConfig:
    """Return the current process configuration."""

    return AtomicConfig.from_env()
