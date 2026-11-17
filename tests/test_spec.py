from pathlib import Path

import pytest

from wazuh_ruletest.spec import SpecError, load_cases

ROOT = Path(__file__).parent.parent


def write(tmp_path, text):
    p = tmp_path / "t.yml"
    p.write_text(text, encoding="utf-8")
    return p


VALID = """
tests:
  - name: ok
    event: "some log"
    expect:
      rule_id: 5710
"""


def test_example_file_loads():
    cases = load_cases(ROOT / "examples" / "sshd.yml")
    assert len(cases) == 2
    assert cases[0].expect.rule_id == "5710"
    assert cases[1].expect.alert is False


def test_numbers_become_strings(tmp_path):
    p = write(tmp_path, """
tests:
  - event: "x"
    expect:
      rule_id: 5710
      level: 5
      fields:
        srcport: 48928
""")
    case = load_cases(p)[0]
    assert case.expect.rule_id == "5710"
    assert case.expect.level == 5
    assert case.expect.fields == {"srcport": "48928"}


def test_alert_defaults_to_true(tmp_path):
    assert load_cases(write(tmp_path, VALID))[0].expect.alert is True


def test_defaults_apply_and_can_be_overridden(tmp_path):
    p = write(tmp_path, """
defaults:
  log_format: json
  location: "agent->/x"
tests:
  - name: a
    event: "e"
    expect: {rule_id: 1}
  - name: b
    event: "e"
    log_format: syslog
    expect: {rule_id: 1}
""")
    a, b = load_cases(p)
    assert (a.log_format, a.location) == ("json", "agent->/x")
    assert (b.log_format, b.location) == ("syslog", "agent->/x")


def test_unnamed_test_gets_a_default_name(tmp_path):
    p = write(tmp_path, 'tests:\n  - event: "e"\n    expect: {rule_id: 1}\n')
    assert load_cases(p)[0].name == "test #1"


def test_typo_in_expect_is_an_error(tmp_path):
    p = write(tmp_path, """
tests:
  - event: "e"
    expect:
      rule: 5710
""")
    with pytest.raises(SpecError, match="unknown key"):
        load_cases(p)


def test_typo_in_test_is_an_error(tmp_path):
    p = write(tmp_path, """
tests:
  - event: "e"
    expects: {rule_id: 1}
""")
    with pytest.raises(SpecError, match="unknown key"):
        load_cases(p)


def test_typo_at_top_level_is_an_error(tmp_path):
    p = write(tmp_path, VALID + "\ntest: []\n")
    with pytest.raises(SpecError, match="unknown key"):
        load_cases(p)


def test_missing_event(tmp_path):
    p = write(tmp_path, "tests:\n  - name: x\n    expect: {rule_id: 1}\n")
    with pytest.raises(SpecError, match="event"):
        load_cases(p)


def test_missing_expect(tmp_path):
    p = write(tmp_path, 'tests:\n  - event: "e"\n')
    with pytest.raises(SpecError, match="expect"):
        load_cases(p)


def test_empty_expect(tmp_path):
    p = write(tmp_path, 'tests:\n  - event: "e"\n    expect: {}\n')
    with pytest.raises(SpecError, match="expect"):
        load_cases(p)


def test_empty_tests_list(tmp_path):
    with pytest.raises(SpecError, match="non-empty"):
        load_cases(write(tmp_path, "tests: []\n"))


def test_alert_must_be_boolean(tmp_path):
    p = write(tmp_path, 'tests:\n  - event: "e"\n    expect: {alert: "no"}\n')
    with pytest.raises(SpecError, match="true or false"):
        load_cases(p)


def test_level_must_be_a_whole_number(tmp_path):
    p = write(tmp_path, 'tests:\n  - event: "e"\n    expect: {level: high}\n')
    with pytest.raises(SpecError, match="whole number"):
        load_cases(p)


def test_missing_file():
    with pytest.raises(SpecError, match="not found"):
        load_cases("does/not/exist.yml")


def test_invalid_yaml(tmp_path):
    with pytest.raises(SpecError, match="not valid YAML"):
        load_cases(write(tmp_path, "tests: [unclosed"))