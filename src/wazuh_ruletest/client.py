from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3


class WazuhError(Exception):
    """Raised when the Wazuh API cannot be used as expected."""


@dataclass
class LogtestResult:
    alert: bool
    rule_id: str | None
    level: int | None
    description: str | None
    decoder: str | None
    fields: dict[str, Any]
    raw: dict[str, Any] = field(repr=False)


class WazuhClient:
    def __init__(self, url, user, password, verify=True, timeout=10):
        self.url = url.rstrip("/")
        self._auth = (user, password)
        self.timeout = timeout
        self._token = None
        self._http = requests.Session()
        self._http.verify = verify
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self):
        r = self._http.post(
            f"{self.url}/security/user/authenticate",
            params={"raw": "true"},
            auth=self._auth,
            timeout=self.timeout,
        )
        if r.status_code == 401:
            raise WazuhError("Login failed (401): check the Wazuh API username/password")
        r.raise_for_status()
        self._token = r.text.strip()

    def _headers(self):
        if not self._token:
            self.login()
        return {"Authorization": f"Bearer {self._token}"}

    def logtest(self, event, log_format="syslog", location="master->/var/log/syslog"):
        body = {"log_format": log_format, "location": location, "event": event}
        r = self._http.put(
            f"{self.url}/logtest", json=body, headers=self._headers(), timeout=self.timeout
        )
        r.raise_for_status()
        data = r.json()["data"]
        try:
            return self._parse(data)
        finally:
            self._close_session(data.get("token"))

    def _close_session(self, token):
        if not token:
            return
        try:
            self._http.delete(
                f"{self.url}/logtest/sessions/{token}",
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException:
            pass  # best effort; Wazuh expires idle sessions anyway

    @staticmethod
    def _parse(data):
        out = data.get("output") or {}
        rule = out.get("rule") or {}
        rule_id = rule.get("id")
        level = rule.get("level")
        return LogtestResult(
            alert=bool(data.get("alert")),
            rule_id=str(rule_id) if rule_id is not None else None,
            level=int(level) if level is not None else None,
            description=rule.get("description"),
            decoder=(out.get("decoder") or {}).get("name"),
            fields=out.get("data") or {},
            raw=data,
        )