# compact-handoff

Generate a compact fresh-chat handoff prompt for ThreatPrism.

Run:

```powershell
Set-Location C:\Projects\ThreatPrismV2
powershell -ExecutionPolicy Bypass -File .\tools\generate-compact-handoff.ps1 -IncludeStatus
```

Return the command output as the handoff prompt. Do not paste long project
files, transcripts, or full handoff docs.
