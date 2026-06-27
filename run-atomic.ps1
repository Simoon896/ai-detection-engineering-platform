# Launch the Atomic Red Team MCP Server on 127.0.0.1 for Cursor.
# Usage: powershell -ExecutionPolicy Bypass -File .\run-atomic.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$envFile = Join-Path $root ".env.atomic.local"
if (-not (Test-Path $envFile)) {
    Write-Error "Missing .env.atomic.local - copy .env.atomic.example to .env.atomic.local and fill it in."
    exit 1
}

# Drop optional WinRM overrides so a removed .env line does not inherit stale shell values.
foreach ($optional in @("ATOMIC_WINRM_AUTH", "ATOMIC_WINRM_DOMAIN")) {
    if (Test-Path "Env:$optional") {
        Remove-Item "Env:$optional"
    }
}

Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $idx = $line.IndexOf("=")
        $k = $line.Substring(0, $idx).Trim()
        $v = $line.Substring($idx + 1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        [System.Environment]::SetEnvironmentVariable($k, $v, "Process")
    }
}

$env:PYTHONPATH = Join-Path $root "src"

$py = Join-Path $root ".venv\Scripts\python.exe"
Write-Host "Starting Atomic Red Team MCP Server on http://$($env:ATOMIC_MCP_HOST):$($env:ATOMIC_MCP_PORT)/mcp"
& $py -m atomic_mcp_server
