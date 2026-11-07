import pathlib
import re

RULE_DIR = pathlib.Path(__file__).resolve().parent.parent / "detections" / "sigma"
REQUIRED_KEYS = ["title", "id", "status", "logsource", "detection", "level", "tags"]


def load(path):
    return path.read_text(encoding="utf-8")


def test_rules_exist():
    rules = list(RULE_DIR.glob("*.yml"))
    assert len(rules) >= 2


def test_required_keys_present():
    for rule in RULE_DIR.glob("*.yml"):
        text = load(rule)
        for key in REQUIRED_KEYS:
            assert re.search(rf"^{key}:", text, re.MULTILINE), f"{rule.name} is missing {key}"


def test_each_rule_has_attack_tag():
    for rule in RULE_DIR.glob("*.yml"):
        assert "attack.t" in load(rule), f"{rule.name} has no ATT&CK technique tag"


def test_condition_present():
    for rule in RULE_DIR.glob("*.yml"):
        assert re.search(r"^\s+condition:", load(rule), re.MULTILINE), f"{rule.name} has no condition"
