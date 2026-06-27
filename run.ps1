# Launch the Wazuh MCP Server (FP-tuning fork) on 127.0.0.1 for Cursor.
# Usage:  powershell -ExecutionPolicy Bypass -File .\run.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$envFile = Join-Path $root ".env.local"
if (-not (Test-Path $envFile)) {
    Write-Error "Missing .env.local - copy .env.local.example to .env.local and fill it in."
    exit 1
}

# Load .env.local into the process environment
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $idx = $line.IndexOf("=")
        $k = $line.Substring(0, $idx).Trim()
        $v = $line.Substring($idx + 1).Trim()
        [System.Environment]::SetEnvironmentVariable($k, $v, "Process")
    }
}

# Make the package importable from src/ without installing
$env:PYTHONPATH = Join-Path $root "src"

$py = Join-Path $root ".venv\Scripts\python.exe"
Write-Host "Starting Wazuh MCP Server on http://$($env:MCP_HOST):$($env:MCP_PORT)/mcp"
& $py -m wazuh_mcp_server
