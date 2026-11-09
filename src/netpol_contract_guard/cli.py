"""Local CLI. Exit codes: 0 pass, 2 policy gate, 3 invalid input/IO."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .engine import run_audit, run_compare, sarif, verdict
from .model import InputError, parse_contracts, parse_snapshot, read_json


def write_atomic(destination: str, contents: str) -> None:
    path = Path(destination)
    if path.is_symlink() or not path.parent.is_dir() or (path.exists() and not path.is_file()):
        raise InputError(f"refusing unsafe output path: {path}")
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".netpol-", suffix=".tmp", delete=False) as handle:
            tmp = Path(handle.name)
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    except OSError as exc:
        raise InputError(f"cannot write output: {exc}") from exc
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Kubernetes NetworkPolicy connectivity-contract gate")
    parser.add_argument("--version", action="version", version=f"netpol-contract-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("audit", "compare"):
        p = sub.add_parser(command, help="Validate contracts" if command == "audit" else "Compare policy changes")
        if command == "audit":
            p.add_argument("--snapshot", required=True)
        else:
            p.add_argument("--before", required=True)
            p.add_argument("--after", required=True)
        p.add_argument("--contracts", required=True)
        p.add_argument("--format", choices=("json", "text"), default="text")
        p.add_argument("--output", help="JSON/text output file; stdout if omitted")
        p.add_argument("--sarif", help="write SARIF 2.1.0 findings")
        p.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "none"), default="high")
    args = parser.parse_args(argv)
    try:
        snap = parse_snapshot(read_json(args.snapshot if args.command == "audit" else args.after))
        contracts = parse_contracts(read_json(args.contracts), snap)
        if args.command == "audit":
            report = run_audit(snap, contracts)
        else:
            before = parse_snapshot(read_json(args.before))
            report = run_compare(before, snap, contracts)
        failed = verdict(report, args.fail_on)
        report["gate"] = "blocked" if failed else "passed"
        report["threshold"] = args.fail_on
        if args.format == "json":
            printable = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        else:
            lines = [f'NetPol ContractGuard {__version__} | mode={report["mode"]} | gate={report["gate"]}',
                     f'contracts={report["summary"]["contracts"]} violations={report["summary"]["violations"]}']
            for row in report["results"]:
                extra = f' drift={row["drift"]}' if "drift" in row else ""
                lines.append(f'{"PASS" if row["pass"] else "FAIL"} [{row["severity"]}] {row["id"]}: {row["source"]} -> {row["destination"]} {row["protocol"]}/{row["port"]} expected={row["expected"]} actual={row["actual"]}{extra}')
            printable = "\n".join(lines) + "\n"
        input_paths = [args.contracts] + ([args.snapshot] if args.command == "audit" else [args.before, args.after])
        output_paths = [x for x in (args.output, args.sarif) if x]
        if len({str(Path(path).resolve()) for path in output_paths}) != len(output_paths):
            raise InputError("output and SARIF paths must be different")
        if any(Path(out).resolve() == Path(source).resolve() for out in output_paths for source in input_paths):
            raise InputError("refusing to overwrite any input snapshot or contracts file")
        if args.output:
            write_atomic(args.output, printable)
        else:
            print(printable, end="")
        if args.sarif:
            write_atomic(args.sarif, json.dumps(sarif(report), ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        return 2 if failed else 0
    except (InputError, OSError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 3
