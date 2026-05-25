param(
    [switch]$IncludeStatus
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$argsList = @('tools\generate_compact_handoff.py')
if ($IncludeStatus) {
    $argsList += '--include-status'
}

python @argsList
