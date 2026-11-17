from wazuh_ruletest.runner import compare
from wazuh_ruletest.spec import Expectation

from .helpers import NO_MATCH, make_result


def test_matching_result_has_no_problems():
    expect = Expectation(rule_id="5710", level=5, decoder="sshd",
                         fields={"srcip": "1.2.3.4"})
    actual = make_result(fields={"srcip": "1.2.3.4", "extra": "ignored"})
    assert compare(expect, actual) == []


def test_unchecked_properties_are_ignored():
    assert compare(Expectation(), make_result(rule_id="999", level=12)) == []


def test_expected_alert_but_nothing_matched():
    problems = compare(Expectation(rule_id="5710"), NO_MATCH)
    assert len(problems) == 1
    assert "expected an alert" in problems[0]
    assert "no rule matched" in problems[0]


def test_expected_no_alert_but_one_fired():
    problems = compare(Expectation(alert=False), make_result())
    assert len(problems) == 1
    assert "expected no alert" in problems[0]
    assert "5710" in problems[0]


def test_no_alert_expectation_passes_when_nothing_matches():
    assert compare(Expectation(alert=False), NO_MATCH) == []


def test_alert_mismatch_hides_follow_up_noise():
    expect = Expectation(rule_id="1", level=9, decoder="x", fields={"a": "b"})
    assert len(compare(expect, NO_MATCH)) == 1


def test_rule_that_matches_without_alerting_is_described():
    quiet = make_result(alert=False, rule_id="5700", level=0)
    problems = compare(Expectation(alert=True), quiet)
    assert "alert=no" in problems[0]
    assert "5700" in problems[0]


def test_wrong_rule_level_and_decoder_are_all_reported():
    expect = Expectation(rule_id="5712", level=12, decoder="nginx")
    problems = compare(expect, make_result())
    assert len(problems) == 3
    assert any("rule_id" in p and "5712" in p for p in problems)
    assert any("level" in p and "12" in p for p in problems)
    assert any("decoder" in p and "nginx" in p for p in problems)


def test_field_mismatch():
    problems = compare(Expectation(fields={"srcip": "1.1.1.1"}),
                       make_result(fields={"srcip": "2.2.2.2"}))
    assert problems == ["field 'srcip': expected '1.1.1.1', got '2.2.2.2'"]


def test_field_not_decoded():
    problems = compare(Expectation(fields={"nosuchfield": "x"}), make_result())
    assert "not decoded" in problems[0]


def test_dotted_path_reaches_nested_fields():
    fields = {"win": {"eventdata": {"image": "C:\\bad.exe"}}}
    expect = Expectation(fields={"win.eventdata.image": "C:\\bad.exe"})
    assert compare(expect, make_result(fields=fields)) == []


def test_literal_dotted_key_still_works():
    expect = Expectation(fields={"data.srcip": "1.2.3.4"})
    assert compare(expect, make_result(fields={"data.srcip": "1.2.3.4"})) == []


def test_numeric_field_values_compare_as_text():
    expect = Expectation(fields={"srcport": "48928"})
    assert compare(expect, make_result(fields={"srcport": 48928})) == []