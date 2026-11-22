"""Command-line entry point for detectctl."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .lint import lint_paths
from .ruletest import run_rule_tests


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detectctl",
        description="Lint, test and ship Sigma detection rules.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint", help="check rules against the quality bar")
    lint.add_argument("path", nargs="?", default="rules", type=Path,
                      help="rules directory (default: rules)")

    test = sub.add_parser("test", help="run each rule against its sample events")
    test.add_argument("path", nargs="?", default="rules", type=Path,
                      help="rules directory (default: rules)")
    test.add_argument("--fixtures", default="tests/fixtures", type=Path,
                      help="fixtures directory (default: tests/fixtures)")
    return parser


def _cmd_lint(args: argparse.Namespace) -> int:
    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory")
        return 2
    checked, findings = lint_paths(args.path)
    for finding in findings:
        print(f"{finding.path}: {finding.message}")
    if findings:
        print(f"{checked} rule(s) checked, {len(findings)} problem(s) found")
        return 1
    print(f"{checked} rule(s) checked, no problems found")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory")
        return 2
    results = run_rule_tests(args.path, args.fixtures)
    if not results:
        print(f"error: no rules found in {args.path}")
        return 2
    failed = 0
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        line = f"{status}  {result.rule.stem} / {result.case}"
        if result.detail:
            line += f"  - {result.detail}"
        print(line)
        failed += 0 if result.ok else 1
    print(f"{len(results)} case(s) run, {len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "lint":
        return _cmd_lint(args)
    if args.command == "test":
        return _cmd_test(args)
    return 2
