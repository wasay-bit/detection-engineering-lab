# Atomic Red Team test notes

Run these only in an isolated lab VM you own.

| Technique | Test | How to run (PowerShell, as admin) |
|---|---|---|
| T1059.001 | Encoded PowerShell | `Invoke-AtomicTest T1059.001 -TestNumbers 1` |
| T1053.005 | Scheduled task | `Invoke-AtomicTest T1053.005 -TestNumbers 1` |

After each test, confirm the matching rule fired in the SIEM, then run the cleanup command with `-Cleanup`.
