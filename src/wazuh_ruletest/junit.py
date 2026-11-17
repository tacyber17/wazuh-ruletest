from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .runner import CaseResult, Status

_ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def _clean(text: str) -> str:
    return _ILLEGAL_XML.sub("?", text)


def write_junit(results_by_file: list[tuple[Path, list[CaseResult]]], out_path) -> None:
    root = ET.Element("testsuites")
    total = failures_all = errors_all = 0
    time_all = 0.0

    for path, results in results_by_file:
        failures = sum(r.status is Status.FAIL for r in results)
        errors = sum(r.status is Status.ERROR for r in results)
        duration = sum(r.duration for r in results)
        suite = ET.SubElement(
            root, "testsuite",
            name=_clean(Path(path).as_posix()),
            tests=str(len(results)),
            failures=str(failures),
            errors=str(errors),
            time=f"{duration:.3f}",
        )
        for r in results:
            tc = ET.SubElement(
                suite, "testcase",
                classname=_clean(Path(path).as_posix()),
                name=_clean(r.case.name),
                time=f"{r.duration:.3f}",
            )
            if r.status is not Status.PASS:
                tag = "failure" if r.status is Status.FAIL else "error"
                first = r.problems[0] if r.problems else r.status.value
                node = ET.SubElement(tc, tag, message=_clean(first))
                node.text = _clean("\n".join(r.problems))
        total += len(results)
        failures_all += failures
        errors_all += errors
        time_all += duration

    root.set("tests", str(total))
    root.set("failures", str(failures_all))
    root.set("errors", str(errors_all))
    root.set("time", f"{time_all:.3f}")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(root)
    ET.ElementTree(root).write(out, encoding="utf-8", xml_declaration=True)