import requests

from wazuh_ruletest.client import WazuhError
from wazuh_ruletest.runner import Status, run_case
from wazuh_ruletest.spec import Case, Expectation

from .helpers import make_result


class FakeClient:
    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def logtest(self, event, log_format="syslog", location=""):
        if self.error:
            raise self.error
        return self.result


def case(**expect):
    return Case(name="c", event="e", log_format="syslog", location="loc",
                expect=Expectation(**expect), source="t.yml")


def test_pass():
    res = run_case(FakeClient(make_result()), case(rule_id="5710"))
    assert res.status is Status.PASS
    assert res.problems == []


def test_fail():
    res = run_case(FakeClient(make_result()), case(rule_id="9999"))
    assert res.status is Status.FAIL
    assert res.problems


def test_wazuh_error_is_error_not_fail():
    res = run_case(FakeClient(error=WazuhError("boom")), case(rule_id="1"))
    assert res.status is Status.ERROR
    assert "boom" in res.problems[0]


def test_network_error_is_error_not_fail():
    err = requests.ConnectionError("unreachable")
    res = run_case(FakeClient(error=err), case(rule_id="1"))
    assert res.status is Status.ERROR