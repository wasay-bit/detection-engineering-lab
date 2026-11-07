# Structure checks for the Sigma rules.
#
# These tests don't run the rules against real logs. They check that each
# rule file has the parts a Sigma rule needs, so simple mistakes get caught.
# Run them with:  python -m pytest tests/
import pathlib
import re

# Find the detections/sigma folder, relative to this test file.
RULE_DIR = pathlib.Path(__file__).resolve().parent.parent / "detections" / "sigma"

# Top-level fields every rule should have.
REQUIRED_KEYS = ["title", "id", "status", "logsource", "detection", "level", "tags"]


# Read a rule file as text.
def load(path):
    return path.read_text(encoding="utf-8")


# There should be at least two rules in the folder.
def test_rules_exist():
    rules = list(RULE_DIR.glob("*.yml"))
    assert len(rules) >= 2


# Each required field should appear at the start of a line in each rule.
# The ^ anchors the match to the start of a line, and re.MULTILINE makes
# ^ work on every line, not just the first.
def test_required_keys_present():
    for rule in RULE_DIR.glob("*.yml"):
        text = load(rule)
        for key in REQUIRED_KEYS:
            assert re.search(rf"^{key}:", text, re.MULTILINE), f"{rule.name} is missing {key}"


# Each rule should map to at least one ATT&CK technique (tags look like attack.t1059.001).
def test_each_rule_has_attack_tag():
    for rule in RULE_DIR.glob("*.yml"):
        assert "attack.t" in load(rule), f"{rule.name} has no ATT&CK technique tag"


# Each rule needs a condition line, which says how the selections combine.
def test_condition_present():
    for rule in RULE_DIR.glob("*.yml"):
        assert re.search(r"^\s+condition:", load(rule), re.MULTILINE), f"{rule.name} has no condition"
