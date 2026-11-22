"""Sigma -> KQL conversion for Microsoft Sentinel / Defender XDR."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

# target name -> (pipeline module, pipeline factory function)
TARGETS = {
    "xdr": ("microsoftxdr", "microsoft_xdr_pipeline"),
    "asim": ("sentinelasim", "sentinel_asim_pipeline"),
    "azuremonitor": ("azuremonitor", "azure_monitor_pipeline"),
}


class ConversionError(Exception):
    """A rule could not be converted."""


@dataclass
class ConversionResult:
    rule: Path
    query: str | None
    error: str | None


def _pipeline(target: str):
    try:
        module, factory = TARGETS[target]
    except KeyError:
        choices = ", ".join(sorted(TARGETS))
        raise ConversionError(f"unknown target '{target}' (choose from: {choices})") from None
    return getattr(importlib.import_module(f"sigma.pipelines.{module}"), factory)()


def convert_rule(path: Path, target: str) -> str:
    """Convert one Sigma rule file to a KQL query for the given target."""
    pipeline = _pipeline(target)
    try:
        # Load fresh on every call: pySigma pipelines rewrite rule objects in
        # place, so reusing one rule across targets hands the second pipeline
        # fields the first one already renamed.
        collection = SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8"))
        queries = KustoBackend(pipeline).convert(collection)
    except (SigmaError, yaml.YAMLError, OSError) as exc:
        raise ConversionError(str(exc)) from exc
    if len(queries) != 1:
        raise ConversionError(f"expected 1 query, got {len(queries)}")
    return queries[0]


def convert_paths(root: Path, target: str) -> list[ConversionResult]:
    """Convert every rule under root. Errors are collected, not raised."""
    results = []
    for path in sorted(Path(root).rglob("*.yml")):
        try:
            results.append(ConversionResult(path, convert_rule(path, target), None))
        except ConversionError as exc:
            results.append(ConversionResult(path, None, str(exc)))
    return results
