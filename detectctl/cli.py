"""Command-line entry point for detectctl."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .lint import lint_paths


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "lint":
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

    return 2
