from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class SpecError(Exception):
    """A test file is missing, unreadable, or written incorrectly."""


ALLOWED_TOP = {"suite", "defaults", "tests"}
ALLOWED_DEFAULTS = {"log_format", "location"}
ALLOWED_TEST = {"name", "event", "log_format", "location", "expect"}
ALLOWED_EXPECT = {"alert", "rule_id", "level", "decoder", "fields"}

DEFAULT_FORMAT = "syslog"
DEFAULT_LOCATION = "master->/var/log/syslog"


@dataclass
class Expectation:
    alert: bool = True
    rule_id: str | None = None
    level: int | None = None
    decoder: str | None = None
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class Case:
    name: str
    event: str
    log_format: str
    location: str
    expect: Expectation
    source: str


def _check_keys(obj: dict, allowed: set, where: str) -> None:
    unknown = set(obj) - allowed
    if unknown:
        raise SpecError(
            f"{where}: unknown key(s) {sorted(map(str, unknown))}; "
            f"allowed keys are {sorted(allowed)}"
        )


def _parse_expect(raw: Any, where: str) -> Expectation:
    if not isinstance(raw, dict) or not raw:
        raise SpecError(f"{where}: 'expect' is required (for example: rule_id: 5710)")
    _check_keys(raw, ALLOWED_EXPECT, f"{where} (expect)")

    alert = raw.get("alert", True)
    if not isinstance(alert, bool):
        raise SpecError(f"{where}: 'alert' must be true or false")

    level = raw.get("level")
    if level is not None:
        if isinstance(level, bool) or not isinstance(level, int):
            raise SpecError(f"{where}: 'level' must be a whole number")

    fields = raw.get("fields") or {}
    if not isinstance(fields, dict):
        raise SpecError(f"{where}: 'fields' must be a mapping like srcip: 1.2.3.4")

    rule_id = raw.get("rule_id")
    decoder = raw.get("decoder")
    return Expectation(
        alert=alert,
        rule_id=str(rule_id) if rule_id is not None else None,
        level=level,
        decoder=str(decoder) if decoder is not None else None,
        fields={str(k): str(v) for k, v in fields.items()},
    )


def load_cases(path: str | Path) -> list[Case]:
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SpecError(f"{path}: file not found") from None
    except yaml.YAMLError as exc:
        raise SpecError(f"{path}: not valid YAML: {exc}") from None

    if not isinstance(doc, dict):
        raise SpecError(f"{path}: top level must be a mapping with a 'tests' list")
    _check_keys(doc, ALLOWED_TOP, str(path))

    defaults = doc.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise SpecError(f"{path}: 'defaults' must be a mapping")
    _check_keys(defaults, ALLOWED_DEFAULTS, f"{path} (defaults)")

    tests = doc.get("tests")
    if not isinstance(tests, list) or not tests:
        raise SpecError(f"{path}: 'tests' must be a non-empty list")

    cases: list[Case] = []
    for i, raw in enumerate(tests, start=1):
        where = f"{path}: test #{i}"
        if not isinstance(raw, dict):
            raise SpecError(f"{where}: each test must be a mapping")
        _check_keys(raw, ALLOWED_TEST, where)

        name = str(raw.get("name") or f"test #{i}")
        where = f"{path}: '{name}'"

        event = raw.get("event")
        if not isinstance(event, str) or not event.strip():
            raise SpecError(f"{where}: 'event' (the raw log line) is required")

        cases.append(
            Case(
                name=name,
                event=event.strip(),
                log_format=raw.get("log_format", defaults.get("log_format", DEFAULT_FORMAT)),
                location=raw.get("location", defaults.get("location", DEFAULT_LOCATION)),
                expect=_parse_expect(raw.get("expect"), where),
                source=str(path),
            )
        )
    return cases