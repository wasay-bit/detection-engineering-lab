# Runs each Sigma rule against sample events, to check that it fires on the
# events it should and stays quiet on the ones it shouldn't.
#
# Each rule in detections/sigma/ needs a matching sample file in
# tests/sample_events/ with the same name ending in .jsonl. Each line is one
# JSON object: {"expect": true or false, "note": "...", "event": {...}}.
#
# This is a small evaluator for the Sigma syntax these rules use. It is not
# the full Sigma engine. It supports:
#   - field equality, and |contains, |startswith, |endswith
#   - lists of values (any value may match)
#   - selections (all fields must match) and conditions with and / or / not / parentheses
# Anything else raises an error, so an unsupported rule fails loudly instead of
# passing by accident.
#
# Matching ignores case, which is the Sigma default for Windows fields.
#
# Run with:  python -m pytest tests/

import json
import pathlib
import re

import pytest
import yaml

RULE_DIR = pathlib.Path(__file__).resolve().parent.parent / "detections" / "sigma"
SAMPLE_DIR = pathlib.Path(__file__).resolve().parent / "sample_events"

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith"}
CONDITION_WORDS = {"and", "or", "not"}


def match_value(event_value, modifier, pattern):
    if event_value is None:
        return False
    actual = str(event_value).lower()
    expected = str(pattern).lower()
    if modifier is None:
        return actual == expected
    if modifier == "contains":
        return expected in actual
    if modifier == "startswith":
        return actual.startswith(expected)
    if modifier == "endswith":
        return actual.endswith(expected)
    raise ValueError(f"unsupported modifier: {modifier}")


def match_field(event, field_spec, value):
    parts = field_spec.split("|")
    field, modifiers = parts[0], parts[1:]
    if len(modifiers) > 1:
        raise ValueError(f"only one modifier per field is supported: {field_spec}")
    modifier = modifiers[0] if modifiers else None
    if modifier is not None and modifier not in SUPPORTED_MODIFIERS:
        raise ValueError(f"unsupported modifier: {modifier}")
    values = value if isinstance(value, list) else [value]
    # Any listed value may match.
    return any(match_value(event.get(field), modifier, v) for v in values)


def match_selection(event, selection):
    if not isinstance(selection, dict):
        raise ValueError("only map-style selections are supported")
    # Every field in a selection must match.
    return all(match_field(event, k, v) for k, v in selection.items())


def eval_condition(condition, results):
    # Only allow names, and/or/not, and parentheses. Anything else is rejected.
    token_pattern = r"\(|\)|[A-Za-z_][A-Za-z0-9_]*"
    leftover = re.sub(token_pattern, "", condition).strip()
    if leftover:
        raise ValueError(f"unsupported syntax in condition: {leftover!r}")
    expression = []
    for token in re.findall(token_pattern, condition):
        if token in ("(", ")") or token in CONDITION_WORDS:
            expression.append(token)
        elif token in results:
            expression.append(f"R[{token!r}]")
        else:
            raise ValueError(f"condition uses unknown selection: {token}")
    return bool(eval(" ".join(expression), {"__builtins__": {}}, {"R": results}))


def evaluate(rule, event):
    detection = rule["detection"]
    results = {
        name: match_selection(event, body)
        for name, body in detection.items()
        if name != "condition"
    }
    return eval_condition(detection["condition"], results)


def load_rule(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_samples(path):
    samples = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        assert "expect" in item and "event" in item, f"{path.name} line {line_no} needs expect and event"
        samples.append((line_no, item))
    return samples


RULES = sorted(RULE_DIR.glob("*.yml"))


# ---- Each rule has samples -------------------------------------------------

@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.name)
def test_rule_has_sample_file(rule_path):
    sample = SAMPLE_DIR / (rule_path.stem + ".jsonl")
    assert sample.exists(), f"add {sample.name} with sample events for {rule_path.name}"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.name)
def test_rule_has_positive_and_negative_samples(rule_path):
    samples = load_samples(SAMPLE_DIR / (rule_path.stem + ".jsonl"))
    expects = {item["expect"] for _, item in samples}
    assert expects == {True, False}, f"{rule_path.name} needs both should-fire and should-not-fire samples"


# ---- The rules behave as their samples say ---------------------------------

def sample_cases():
    cases = []
    for rule_path in RULES:
        sample = SAMPLE_DIR / (rule_path.stem + ".jsonl")
        if not sample.exists():
            continue
        for line_no, item in load_samples(sample):
            cases.append(pytest.param(rule_path, line_no, item, id=f"{rule_path.stem}:{line_no}"))
    return cases


@pytest.mark.parametrize("rule_path,line_no,item", sample_cases())
def test_rule_matches_sample(rule_path, line_no, item):
    rule = load_rule(rule_path)
    got = evaluate(rule, item["event"])
    assert got == item["expect"], (
        f"{rule_path.name} line {line_no}: expected {item['expect']}, got {got}. {item.get('note', '')}"
    )


# ---- The evaluator itself --------------------------------------------------

def test_list_values_match_any_and_fields_match_all():
    rule = {"detection": {
        "sel": {"CommandLine|contains": ["-a", "-b"], "Image|endswith": ".exe"},
        "condition": "sel",
    }}
    assert evaluate(rule, {"CommandLine": "x -b y", "Image": "C:\\t.exe"})
    assert not evaluate(rule, {"CommandLine": "x -b y", "Image": "C:\\t.dll"})
    assert not evaluate(rule, {"CommandLine": "nothing", "Image": "C:\\t.exe"})


def test_matching_ignores_case():
    rule = {"detection": {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"}}
    assert evaluate(rule, {"Image": "C:\\WINDOWS\\POWERSHELL.EXE"})


def test_not_and_or_conditions():
    rule = {"detection": {
        "a": {"X": 1},
        "b": {"Y": 2},
        "condition": "(a or b) and not b",
    }}
    assert evaluate(rule, {"X": 1})
    assert not evaluate(rule, {"Y": 2})
    assert not evaluate(rule, {})


def test_unsupported_syntax_fails_loudly():
    with pytest.raises(ValueError):
        evaluate({"detection": {"sel": {"X": 1}, "condition": "1 of sel*"}}, {"X": 1})
    with pytest.raises(ValueError):
        evaluate({"detection": {"sel": {"X|re": "a"}, "condition": "sel"}}, {"X": "a"})
    with pytest.raises(ValueError):
        evaluate({"detection": {"sel": {"X": 1}, "condition": "missing"}}, {"X": 1})
