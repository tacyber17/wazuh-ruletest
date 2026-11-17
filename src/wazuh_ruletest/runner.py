from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests
import time

from .client import LogtestResult, WazuhClient, WazuhError
from .spec import Case, Expectation


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class CaseResult:
    case: Case
    status: Status
    problems: list[str] = field(default_factory=list)
    actual: LogtestResult | None = None
    duration: float = 0.0


_MISSING = object()


def _lookup(fields: dict[str, Any], path: str) -> Any:
    """Find a decoded field by literal key, or by dotted path like a.b.c."""
    if path in fields:
        return fields[path]
    current: Any = fields
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _describe(actual: LogtestResult) -> str:
    if actual.rule_id is None:
        return "no rule matched"
    alert = "yes" if actual.alert else "no"
    return (
        f"rule {actual.rule_id} matched "
        f"(level {actual.level}, alert={alert}): {actual.description}"
    )


def compare(expect: Expectation, actual: LogtestResult) -> list[str]:
    """Return a list of human-readable problems; empty means the case passed."""
    if expect.alert != actual.alert:
        want = "an alert" if expect.alert else "no alert"
        return [f"expected {want}, but {_describe(actual)}"]

    problems: list[str] = []

    if expect.rule_id is not None and expect.rule_id != actual.rule_id:
        problems.append(f"rule_id: expected {expect.rule_id}, got {actual.rule_id}")

    if expect.level is not None and expect.level != actual.level:
        problems.append(f"level: expected {expect.level}, got {actual.level}")

    if expect.decoder is not None and expect.decoder != actual.decoder:
        problems.append(f"decoder: expected {expect.decoder}, got {actual.decoder}")

    for key, want in expect.fields.items():
        got = _lookup(actual.fields, key)
        if got is _MISSING:
            problems.append(f"field '{key}': expected '{want}', but it was not decoded")
        elif str(got) != want:
            problems.append(f"field '{key}': expected '{want}', got '{got}'")

    return problems


def run_case(client: WazuhClient, case: Case) -> CaseResult:
    started = time.perf_counter()
    try:
        actual = client.logtest(
            case.event, log_format=case.log_format, location=case.location
        )
    except (WazuhError, requests.RequestException) as exc:
        return CaseResult(
            case, Status.ERROR, [f"could not run test: {exc}"],
            duration=time.perf_counter() - started,
        )

    problems = compare(case.expect, actual)
    status = Status.FAIL if problems else Status.PASS
    return CaseResult(case, status, problems, actual, time.perf_counter() - started)


def run_cases(client: WazuhClient, cases: list[Case]) -> list[CaseResult]:
    return [run_case(client, case) for case in cases]