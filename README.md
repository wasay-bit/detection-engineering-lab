# Detection Engineering Lab 

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
LEARNING.md         Walkthrough of the rules and tests
```

## Running the checks

```
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

Two kinds of checks run:

- `tests/test_rules.py` checks that each rule has the required parts (title, id, logsource, detection, condition, ATT&CK tag).
- `tests/test_rule_matching.py` runs each rule against sample events in `tests/sample_events/`. Each rule has events it should fire on and events it should not. The matcher handles the Sigma syntax these rules use (equality, `contains`, `startswith`, `endswith`, lists, `and`, `or`, `not`). It is not the full Sigma engine, and it fails loudly on anything it doesn't support.

Automatic runs on every push through GitHub Actions are planned but not yet active.

## Safety

Run Atomic Red Team tests only in an isolated lab VM that you own. Never run them on production or someone else's machine.

## Limitations

- Rules are not tuned for a real environment and will produce false positives.
- Rules are tested against hand-written sample events, not live Sysmon or Security logs.
- Known gap in the encoded PowerShell rule: it looks for flags with a space after them, so a flag at the very end of a command line is missed. The sample file has this case marked as a known gap.
