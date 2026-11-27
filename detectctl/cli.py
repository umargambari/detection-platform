"""Command-line entry point for detectctl."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .convert import TARGETS, convert_paths
from .lint import lint_paths
from .render import RenderError, render_template
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
    convert = sub.add_parser("convert", help="convert rules to KQL for Microsoft Sentinel")
    convert.add_argument("path", nargs="?", default="rules", type=Path,
                         help="rules directory (default: rules)")
    convert.add_argument("--target", choices=sorted(TARGETS), default="azuremonitor",
                         help="query dialect (default: azuremonitor)")
    convert.add_argument("--out", type=Path,
                         help="write one .kql file per rule into this directory (default: print)")
    render = sub.add_parser("render", help="render rules as Sentinel analytics rules (ARM template)")
    render.add_argument("path", nargs="?", default="rules", type=Path,
                        help="rules directory (default: rules)")
    render.add_argument("--out", type=Path,
                        help="write the ARM template to this file (default: print)")
    render.add_argument("--frequency", default="PT5M",
                        help="how often each rule runs, ISO 8601 (default: PT5M)")
    render.add_argument("--period", default="PT1H",
                        help="lookback window of each run, ISO 8601 (default: PT1H)")
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


def _cmd_convert(args: argparse.Namespace) -> int:
    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory")
        return 2
    results = convert_paths(args.path, args.target)
    if not results:
        print(f"error: no rules found in {args.path}")
        return 2
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    failed = 0
    for result in results:
        if result.error:
            print(f"FAIL  {result.rule.stem}  - {result.error}")
            failed += 1
        elif args.out:
            dest = args.out / f"{result.rule.stem}.kql"
            dest.write_text(result.query + "\n", encoding="utf-8")
            print(f"OK    {result.rule.stem} -> {dest}")
        else:
            print(f"// {result.rule.stem}\n{result.query}\n")
    print(f"{len(results)} rule(s) converted for {args.target}, {failed} failed")
    return 1 if failed else 0


def _cmd_render(args: argparse.Namespace) -> int:
    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory")
        return 2
    if not any(args.path.rglob("*.yml")):
        print(f"error: no rules found in {args.path}")
        return 2
    try:
        template = render_template(args.path, frequency=args.frequency, period=args.period)
    except RenderError as exc:
        print(f"FAIL  {exc}")
        return 1
    text = json.dumps(template, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{len(template['resources'])} rule(s) rendered -> {args.out}")
    else:
        print(text, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "lint":
        return _cmd_lint(args)
    if args.command == "test":
        return _cmd_test(args)
    if args.command == "convert":
        return _cmd_convert(args)
    if args.command == "render":
        return _cmd_render(args)
    return 2
