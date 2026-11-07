# Detection Engineering Lab (practice project)



A small detection-engineering practice repo: two Sigma rules for Windows endpoints, mapped to MITRE ATT&CK, with Atomic Red Team test notes and a basic test that checks rule structure.

## Threat model

- **Assets:** Windows workstations in a test lab.
- **Threats covered:** encoded PowerShell execution (T1059.001) and scheduled task persistence (T1053.005).
- **Out of scope:** network detection, cloud logs, and EDR tuning.
- **Assumption:** logs are collected with Sysmon (process creation) and the Windows Security log (event 4698).

## Layout

```
detections/sigma/   Sigma rules, one per technique
tests/atomic/       Notes on running Atomic Red Team tests
tests/              Structure checks for the rules
attack_mapping.md   Rule-to-technique table
```

## Running the checks

```
python -m pytest tests/
```

## Safety

Run Atomic Red Team tests only in an isolated lab VM that you own. Never run them on production or someone else's machine.

## Limitations

- Rules are not tuned for a real environment and will produce false positives.
- Rule structure is checked, but the rules are not tested against live Sysmon or Security logs.
