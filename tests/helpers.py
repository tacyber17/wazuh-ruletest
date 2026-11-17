from wazuh_ruletest.client import LogtestResult


def make_result(alert=True, rule_id="5710", level=5, description="sshd: test rule",
                decoder="sshd", fields=None):
    return LogtestResult(
        alert=alert,
        rule_id=rule_id,
        level=level,
        description=description,
        decoder=decoder,
        fields=fields if fields is not None else {},
        raw={},
    )


NO_MATCH = make_result(alert=False, rule_id=None, level=None,
                       description=None, decoder=None)