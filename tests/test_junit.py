import xml.etree.ElementTree as ET
from pathlib import Path

from wazuh_ruletest.junit import write_junit
from wazuh_ruletest.runner import CaseResult, Status
from wazuh_ruletest.spec import Case, Expectation


def make_case(name):
    return Case(name=name, event="e", log_format="syslog",
                location="l", expect=Expectation(), source="t.yml")


def sample_results():
    return [
        CaseResult(make_case("good"), Status.PASS, duration=0.1),
        CaseResult(make_case("bad"), Status.FAIL,
                   ["rule_id: expected 1, got 2", "level: expected 3, got 4"],
                   duration=0.2),
        CaseResult(make_case("broken"), Status.ERROR,
                   ["could not run test: boom"], duration=0.3),
    ]


def test_counts_and_structure(tmp_path):
    out = tmp_path / "reports" / "junit.xml"
    write_junit([(Path("rules/sshd.yml"), sample_results())], out)

    root = ET.parse(out).getroot()
    assert (root.get("tests"), root.get("failures"), root.get("errors")) == ("3", "1", "1")

    suite = root.find("testsuite")
    assert suite.get("name") == "rules/sshd.yml"
    good, bad, broken = suite.findall("testcase")
    assert good.find("failure") is None and good.find("error") is None
    assert "rule_id" in bad.find("failure").get("message")
    assert "level" in bad.find("failure").text
    assert broken.find("error") is not None


def test_illegal_xml_characters_do_not_break_the_report(tmp_path):
    out = tmp_path / "junit.xml"
    nasty = CaseResult(make_case("nul\x00name"), Status.FAIL, ["bad \x01 byte"])
    write_junit([(Path("t.yml"), [nasty])], out)
    ET.parse(out)  # raises if the XML is invalid