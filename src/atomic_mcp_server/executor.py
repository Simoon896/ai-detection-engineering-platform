"""Execution transports for Atomic Red Team PowerShell tests."""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from atomic_mcp_server.config import AtomicConfig, resolve_winrm_username, winrm_auth_attempts

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


@dataclass(frozen=True)
class ExecutionResult:
    """Result from a remote PowerShell command."""

    command: str
    stdout: str
    stderr: str
    exit_code: int
    start_utc: str
    end_utc: str


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_technique(technique: Any) -> str:
    if not isinstance(technique, str) or not TECHNIQUE_RE.match(technique.strip()):
        raise ValueError("technique must match T1234 or T1234.001")
    return technique.strip()


def validate_test_number(test_number: Any) -> int:
    try:
        number = int(test_number)
    except (TypeError, ValueError) as exc:
        raise ValueError("test_number must be an integer") from exc
    if number < 1 or number > 999:
        raise ValueError("test_number must be between 1 and 999")
    return number


def ps_quote(value: str) -> str:
    """Single-quote a PowerShell literal."""

    return "'" + value.replace("'", "''") + "'"


class Executor(ABC):
    """Abstract executor for one allowlisted Windows test VM."""

    def __init__(self, config: AtomicConfig) -> None:
        self.config = config

    def validate_target(self, target: str | None = None) -> str:
        resolved = (target or self.config.allowed_target).strip()
        if resolved != self.config.allowed_target:
            raise ValueError(f"Target '{resolved}' is not allowlisted for this Atomic MCP server")
        return resolved

    def validate_input_args(self, input_args: dict[str, Any] | None) -> dict[str, str]:
        if not input_args:
            return {}
        if len(input_args) > 20:
            raise ValueError("input_args may contain at most 20 values")
        clean: dict[str, str] = {}
        for key, value in input_args.items():
            if not isinstance(key, str) or not SAFE_ARG_RE.match(key):
                raise ValueError(f"Invalid input argument name: {key!r}")
            text = str(value)
            if len(text) > 256:
                raise ValueError(f"Input argument '{key}' is too long")
            clean[key] = text
        return clean

    def build_input_args(self, input_args: dict[str, str]) -> str:
        if not input_args:
            return ""
        pairs = "; ".join(f"{key} = {ps_quote(value)}" for key, value in sorted(input_args.items()))
        return f" -InputArgs @{{ {pairs} }}"

    def atomic_script(
        self,
        action: str,
        technique: str,
        test_number: int | None = None,
        input_args: dict[str, Any] | None = None,
    ) -> str:
        technique = validate_technique(technique)
        args = self.validate_input_args(input_args)
        command = f"Invoke-AtomicTest {technique}"
        if test_number is not None:
            command += f" -TestNumbers {validate_test_number(test_number)}"
        if action == "prereq":
            command += " -GetPrereqs"
        elif action == "cleanup":
            command += " -Cleanup"
        elif action != "run":
            raise ValueError("action must be one of: run, prereq, cleanup")
        command += self.build_input_args(args)
        return f"Import-Module Invoke-AtomicRedTeam; {command}"

    @abstractmethod
    async def run_script(self, script: str, target: str | None = None) -> ExecutionResult:
        """Run PowerShell in or against the configured VM."""

    async def run_atomic(
        self,
        technique: str,
        test_number: int,
        input_args: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        return await self.run_script(self.atomic_script("run", technique, test_number, input_args))

    async def check_prereqs(self, technique: str, test_number: int) -> ExecutionResult:
        return await self.run_script(self.atomic_script("prereq", technique, test_number))

    async def cleanup_atomic(self, technique: str, test_number: int) -> ExecutionResult:
        return await self.run_script(self.atomic_script("cleanup", technique, test_number))


class HyperVDirectExecutor(Executor):
    """Execute PowerShell through Hyper-V PowerShell Direct."""

    def build_argv(self, script: str, target: str | None = None) -> list[str]:
        vm_name = self.validate_target(target)
        command = (
            f"Invoke-Command -VMName {ps_quote(vm_name)} "
            f"-ScriptBlock {{ Set-Location {ps_quote(self.config.atomics_path)}; {script} }}"
        )
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]

    async def run_script(self, script: str, target: str | None = None) -> ExecutionResult:
        argv = self.build_argv(script, target)
        start = utc_now()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=self.config.max_runtime_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            end = utc_now()
            return ExecutionResult(" ".join(argv), "", "Command timed out", 124, start, end)
        end = utc_now()
        return ExecutionResult(
            command=" ".join(argv),
            stdout=stdout_b.decode("utf-8", errors="replace")[: self.config.output_limit_bytes],
            stderr=stderr_b.decode("utf-8", errors="replace")[: self.config.output_limit_bytes],
            exit_code=proc.returncode or 0,
            start_utc=start,
            end_utc=end,
        )


class WinrmExecutor(Executor):
    """Execute PowerShell over WinRM HTTPS using pypsrp."""

    async def run_script(self, script: str, target: str | None = None) -> ExecutionResult:
        host = self.validate_target(target)
        if not self.config.winrm_username or not self.config.winrm_password:
            raise ValueError("ATOMIC_WINRM_USERNAME and ATOMIC_WINRM_PASSWORD are required for winrm transport")

        start = utc_now()

        def _run() -> ExecutionResult:
            try:
                from pypsrp.client import Client
            except ImportError as exc:
                raise RuntimeError("pypsrp is required for ATOMIC_TRANSPORT=winrm") from exc

            from pypsrp.exceptions import AuthenticationError

            principal = resolve_winrm_username(
                self.config.winrm_username,
                self.config.winrm_domain,
            )
            client_kwargs = {
                "username": principal,
                "password": self.config.winrm_password,
                "ssl": True,
                "port": self.config.winrm_port,
                "cert_validation": self.config.winrm_verify_tls,
            }
            last_auth_error: Exception | None = None
            output = None
            streams = None
            had_errors = False
            for auth in winrm_auth_attempts(self.config):
                try:
                    client = Client(host, auth=auth, **client_kwargs)
                    output, streams, had_errors = client.execute_ps(
                        f"Set-Location {ps_quote(self.config.atomics_path)}; {script}"
                    )
                    last_auth_error = None
                    break
                except AuthenticationError as exc:
                    last_auth_error = exc
            if last_auth_error is not None:
                raise last_auth_error
            stderr = "\n".join(str(stream) for stream in streams.error)
            end = utc_now()
            return ExecutionResult(
                command=f"WinRM:{host}: {script}",
                stdout=str(output)[: self.config.output_limit_bytes],
                stderr=stderr[: self.config.output_limit_bytes],
                exit_code=1 if had_errors else 0,
                start_utc=start,
                end_utc=end,
            )

        return await asyncio.wait_for(asyncio.to_thread(_run), timeout=self.config.max_runtime_seconds)


def create_executor(config: AtomicConfig) -> Executor:
    if config.transport == "winrm":
        return WinrmExecutor(config)
    return HyperVDirectExecutor(config)
