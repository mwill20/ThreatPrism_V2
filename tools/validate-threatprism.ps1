[CmdletBinding()]
param(
    [string]$BaseTemp = "",
    [switch]$SkipEval,
    [switch]$SkipSafety
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if ([string]::IsNullOrWhiteSpace($BaseTemp)) {
    $BaseTemp = ".pytest_tmp_run_ops_ci_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
}

$env:PYTHONPATH = "src"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:THREATPRISM_ENV = "test"
$env:API_AUTH_MODE = "none"
$env:LLM_PROVIDER = "deterministic_demo"
$env:ALLOW_REAL_ACTIONS = "false"
$env:OPENAI_API_KEY = ""
$env:LOCAL_LLM_BASE_URL = ""
$env:VIRUSTOTAL_API_KEY = ""
$env:URLSCAN_API_KEY = ""
$env:ABUSEIPDB_API_KEY = ""

Write-Host "ThreatPrism safe validation starting from $RepoRoot"
Write-Host "Pytest base temp: $BaseTemp"

if (-not $SkipSafety) {
    python tools/check_demo_safety.py --include-untracked
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

python -m pytest -p no:cacheprovider --basetemp $BaseTemp
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipEval) {
    python -m threatprism.evals.cli --fixtures regression_cases.jsonl --output ops_ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if (-not $SkipSafety) {
        python tools/check_demo_safety.py --scan-eval-artifacts
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

Write-Host "ThreatPrism safe validation completed."
