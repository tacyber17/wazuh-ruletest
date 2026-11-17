from __future__ import annotations

import argparse
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from .junit import write_junit

import requests

from .client import WazuhClient, WazuhError
from .runner import CaseResult, Status, run_case
from .spec import SpecError, load_cases

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2

LABELS = {
    Status.PASS: ("PASS", "32"),
    Status.FAIL: ("FAIL", "31"),
    Status.ERROR: ("ERROR", "33"),
}


def _version() -> str:
    try:
        return version("wazuh-ruletest")
    except PackageNotFoundError:
        return "unknown"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        os.system("")  # switches on ANSI escape support in modern Windows terminals
    return True


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            found = sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
            if not found:
                raise SpecError(f"{p}: no .yml or .yaml files found")
            files.extend(found)
        elif p.exists():
            files.append(p)
        else:
            raise SpecError(f"{p}: no such file or directory")
    return files


def _print_result(res: CaseResult, color: bool) -> None:
    label, code = LABELS[res.status]
    print(f"  {_paint(label.ljust(5), code, color)}  {res.case.name}")
    for problem in res.problems:
        print(f"         {problem}")


def cmd_run(args: argparse.Namespace) -> int:
    color = _use_color()
    password = os.environ.get("WAZUH_PASSWORD")

    missing = [
        label
        for label, value in (
            ("--url (or WAZUH_URL)", args.url),
            ("--user (or WAZUH_USER)", args.user),
            ("WAZUH_PASSWORD environment variable", password),
        )
        if not value
    ]
    if missing:
        _err("missing: " + ", ".join(missing))
        return EXIT_ERROR

    try:
        files = collect_files(args.paths)
    except SpecError as exc:
        _err(str(exc))
        return EXIT_ERROR

    loaded, spec_errors = [], []
    for f in files:
        try:
            loaded.append((f, load_cases(f)))
        except SpecError as exc:
            spec_errors.append(str(exc))
    if spec_errors:
        for message in spec_errors:
            _err(message)
        return EXIT_ERROR

    if args.insecure:
        verify = False
        print("warning: TLS certificate verification is disabled (--insecure)", file=sys.stderr)
    else:
        verify = args.ca_cert or True

    client = WazuhClient(args.url, args.user, password, verify=verify, timeout=args.timeout)
    try:
        client.login()
    except WazuhError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except requests.exceptions.SSLError as exc:
        _err(f"TLS problem talking to {args.url}: {exc}")
        print("hint: for a lab with a self-signed certificate, use --insecure "
              "(or --ca-cert FILE)", file=sys.stderr)
        return EXIT_ERROR
    except requests.RequestException as exc:
        _err(f"cannot reach the Wazuh API at {args.url}: {exc}")
        return EXIT_ERROR

    counts = {status: 0 for status in Status}
    all_results = []
    started = time.perf_counter()
    for path, cases in loaded:
        print(f"\n{path}")
        file_results = []
        for case in cases:
            result = run_case(client, case)
            counts[result.status] += 1
            file_results.append(result)
            _print_result(result, color)
            sys.stdout.flush()
        all_results.append((path, file_results))
    elapsed = time.perf_counter() - started

    if args.junit:
        try:
            write_junit(all_results, args.junit)
        except OSError as exc:
            _err(f"could not write JUnit report: {exc}")
            return EXIT_ERROR

    passed, failed, errors = (counts[Status.PASS], counts[Status.FAIL], counts[Status.ERROR])
    summary = f"{passed} passed, {failed} failed, {errors} errors in {elapsed:.1f}s"
    if errors:
        code, exit_code = "33", EXIT_ERROR
    elif failed:
        code, exit_code = "31", EXIT_FAIL
    else:
        code, exit_code = "32", EXIT_OK
    print(f"\n{_paint(summary, code, color)}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuh-ruletest",
        description="Regression tests for Wazuh rules and decoders.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser(
        "run",
        help="run test files against a Wazuh manager",
        description="Run YAML test files through the Wazuh logtest API. "
        "The API password is read from the WAZUH_PASSWORD environment variable.",
    )
    run.add_argument("paths", nargs="+", help="test files or directories")
    run.add_argument("--url", default=os.environ.get("WAZUH_URL"),
                     help="Wazuh API URL, e.g. https://host:55000 (env: WAZUH_URL)")
    run.add_argument("--user", default=os.environ.get("WAZUH_USER"),
                     help="Wazuh API user (env: WAZUH_USER)")
    tls = run.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true",
                     help="do not verify the TLS certificate (lab use only)")
    tls.add_argument("--ca-cert", metavar="FILE",
                     help="CA certificate bundle used to verify the server")
    run.add_argument("--timeout", type=float, default=10.0,
                     help="seconds to wait for each API call (default: 10)")
    run.add_argument("--junit", metavar="FILE",
                     help="also write a JUnit XML report to FILE")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            return cmd_run(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    return EXIT_ERROR