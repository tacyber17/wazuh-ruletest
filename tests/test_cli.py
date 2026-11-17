from pathlib import Path

import pytest
import requests

from wazuh_ruletest import cli
from wazuh_ruletest.client import WazuhError

from .helpers import NO_MATCH, make_result

ROOT = Path(__file__).parent.parent
SSHD_RESULT = make_result(fields={"srcip": "18.18.18.18", "srcuser": "blimey"})


class FakeClient:
    instances = []
    login_error = None

    def __init__(self, url, user, password, verify=True, timeout=10):
        self.verify = verify
        FakeClient.instances.append(self)

    def login(self):
        if FakeClient.login_error:
            raise FakeClient.login_error

    def logtest(self, event, log_format="syslog", location=""):
        return SSHD_RESULT if "sshd" in event else NO_MATCH


@pytest.fixture(autouse=True)
def fake_wazuh(monkeypatch):
    FakeClient.instances = []
    FakeClient.login_error = None
    monkeypatch.setattr(cli, "WazuhClient", FakeClient)
    monkeypatch.setenv("WAZUH_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("WAZUH_USER", "api")
    monkeypatch.setenv("WAZUH_PASSWORD", "pw")


def run(*args):
    return cli.main(["run", *args])


def test_all_pass_exits_0(capsys):
    assert run(str(ROOT / "examples" / "sshd.yml")) == 0
    out = capsys.readouterr().out
    assert "2 passed, 0 failed, 0 errors" in out


def test_failures_exit_1(capsys):
    assert run(str(ROOT / "tests" / "fixtures" / "broken.yml")) == 1
    out = capsys.readouterr().out
    assert "expected 5712, got 5710" in out
    assert "0 passed, 2 failed" in out


def test_directory_runs_every_yaml_file(tmp_path, capsys):
    for name in ("a.yml", "b.yaml"):
        (tmp_path / name).write_text(
            'tests:\n  - event: "sshd x"\n    expect: {rule_id: 5710}\n')
    assert run(str(tmp_path)) == 0
    assert "2 passed" in capsys.readouterr().out


def test_empty_directory_exits_2(tmp_path, capsys):
    assert run(str(tmp_path)) == 2
    assert "no .yml" in capsys.readouterr().err


def test_missing_path_exits_2(capsys):
    assert run("nope.yml") == 2
    assert "no such file" in capsys.readouterr().err


def test_spec_error_exits_2_before_contacting_wazuh(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text('tests:\n  - event: "e"\n    expect: {rule: 1}\n')
    assert run(str(bad)) == 2
    assert "unknown key" in capsys.readouterr().err
    assert FakeClient.instances == []


def test_missing_password_exits_2(monkeypatch, capsys):
    monkeypatch.delenv("WAZUH_PASSWORD")
    assert run(str(ROOT / "examples" / "sshd.yml")) == 2
    assert "WAZUH_PASSWORD" in capsys.readouterr().err


def test_missing_url_exits_2(monkeypatch, capsys):
    monkeypatch.delenv("WAZUH_URL")
    assert run(str(ROOT / "examples" / "sshd.yml")) == 2
    assert "--url" in capsys.readouterr().err


def test_login_failure_exits_2(capsys):
    FakeClient.login_error = WazuhError("Login failed (401)")
    assert run(str(ROOT / "examples" / "sshd.yml")) == 2
    assert "Login failed" in capsys.readouterr().err


def test_tls_error_exits_2_with_hint(capsys):
    FakeClient.login_error = requests.exceptions.SSLError("bad cert")
    assert run(str(ROOT / "examples" / "sshd.yml")) == 2
    assert "--insecure" in capsys.readouterr().err


def test_unreachable_manager_exits_2(capsys):
    FakeClient.login_error = requests.ConnectionError("refused")
    assert run(str(ROOT / "examples" / "sshd.yml")) == 2
    assert "cannot reach" in capsys.readouterr().err


def test_insecure_flag_disables_verification_and_warns(capsys):
    assert run(str(ROOT / "examples" / "sshd.yml"), "--insecure") == 0
    assert FakeClient.instances[0].verify is False
    assert "verification is disabled" in capsys.readouterr().err


def test_tls_verification_is_on_by_default():
    run(str(ROOT / "examples" / "sshd.yml"))
    assert FakeClient.instances[0].verify is True

def test_junit_report_is_written(tmp_path):
    out = tmp_path / "out" / "junit.xml"
    code = run(str(ROOT / "tests" / "fixtures" / "broken.yml"), "--junit", str(out))
    assert code == 1
    assert 'failures="2"' in out.read_text(encoding="utf-8")