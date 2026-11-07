# How the detection lab works



## What a Sigma rule is

A Sigma rule is a YAML file that describes a behavior to detect, in a format that can be converted to many SIEM query languages. Each rule has:
- **Metadata:** title, id, status, description, and log source.
- **Detection:** named selections (what to match) and a `condition` (how to combine them).
- **Triage info:** known false positives, severity level, and ATT&CK tags.

## Rule 1: encoded PowerShell (`proc_creation_encoded_powershell.yml`)

Attackers often run PowerShell with an encoded command so the real command is hidden from a quick look at the logs.

- `selection_image` matches when the program is PowerShell (`powershell.exe` or `pwsh.exe`). The `|endswith` modifier means "the path ends with this text."
- `selection_flags` matches when the command line contains an encoded-command flag.
- `condition: selection_image and selection_flags` means both must be true.

**Think about it:** what legitimate admin scripts might trigger this? That's what the `falsepositives` field is for.

## Rule 2: scheduled task creation (`scheduled_task_creation.yml`)

Windows event 4698 is logged whenever a scheduled task is created. Attackers use tasks to keep running after a reboot.

- `selection` matches event 4698.
- `filter_system` excludes tasks created by machine accounts (names ending in `$`), which reduces noise.
- `condition: selection and not filter_system` keeps the match and drops the filtered cases.

## The ATT&CK mapping

`attack_mapping.md` links each rule to a MITRE ATT&CK technique. The `attack.t...` tags in each rule do the same job in machine-readable form.

## The tests (`tests/test_rules.py`)

The tests don't run the rules against logs. They check that each rule file has the required parts, which catches simple mistakes early.

- `test_rules_exist`: there are at least two rule files.
- `test_required_keys_present`: each rule has the fields listed in `REQUIRED_KEYS`. It uses a regular expression that looks for each key at the start of a line.
- `test_each_rule_has_attack_tag`: each rule has at least one ATT&CK tag.
- `test_condition_present`: each rule has a `condition:` line.

**Try it:** delete the `level:` line from a rule and run `python -m pytest tests/`. Which test fails, and why?

## Testing with Atomic Red Team

`tests/atomic/README.md` lists one Atomic test per technique. Run these only in a lab VM you own. Each test simulates the technique so you can check that your rule fires.

## Exercises

- Write a third rule for a technique you choose, plus its ATT&CK tag and a row in `attack_mapping.md`.
- Add a test that checks each rule's `id` is a valid UUID.
- Think about how you'd tune the PowerShell rule to reduce false positives without missing real attacks.
