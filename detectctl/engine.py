"""A small Sigma evaluator for testing rules against sample events.

Supports field matching with the contains, startswith, endswith and all
modifiers, value lists (OR), selections (AND of fields), and conditions
using and / or / not / parentheses plus "1 of" / "all of" patterns.
Anything else raises UnsupportedRule so a test can never pass silently.
"""

from __future__ import annotations

import fnmatch
import re

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all"}
TOKEN = re.compile(r"\(|\)|[^\s()]+")


class UnsupportedRule(Exception):
    """The rule uses a Sigma feature this evaluator does not implement."""


def _match_value(event_value, operator: str | None, pattern) -> bool:
    if pattern is None:
        return event_value is None
    if event_value is None:
        return False
    needle = str(pattern).lower()
    if "*" in needle or "?" in needle:
        raise UnsupportedRule(f"wildcards are not supported: {pattern!r}")
    haystack = str(event_value).lower()
    if operator == "contains":
        return needle in haystack
    if operator == "startswith":
        return haystack.startswith(needle)
    if operator == "endswith":
        return haystack.endswith(needle)
    return haystack == needle


def _match_field(event: dict, key: str, expected) -> bool:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedRule(f"unsupported modifier(s) {sorted(unknown)} on {field}")
    match_all = "all" in modifiers
    operator = next((m for m in modifiers if m != "all"), None)
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(event.get(field.lower()), operator, v) for v in values]
    return all(results) if match_all else any(results)


def _eval_selection(event: dict, selection) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, key, value) for key, value in selection.items())
    if isinstance(selection, list) and selection and all(
        isinstance(item, dict) for item in selection
    ):
        return any(_eval_selection(event, item) for item in selection)
    raise UnsupportedRule("keyword and plain-list selections are not supported")


class _ConditionParser:
    """Recursive-descent parser: not binds tighter than and, and tighter than or."""

    def __init__(self, condition: str, results: dict[str, bool]):
        self.tokens = TOKEN.findall(condition)
        self.pos = 0
        self.results = results

    def parse(self) -> bool:
        value = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedRule(f"unexpected token in condition: {self.tokens[self.pos]!r}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise UnsupportedRule("condition ended unexpectedly")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._next()
            right = self._and()
            value = value or right
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._next()
            right = self._not()
            value = value and right
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._next()
        if token == "(":
            value = self._or()
            if self._next() != ")":
                raise UnsupportedRule("missing closing parenthesis")
            return value
        if token.lower() in ("1", "all") and self._peek() == "of":
            self._next()
            pattern = self._next()
            names = [
                name for name in self.results
                if pattern == "them" or fnmatch.fnmatchcase(name, pattern)
            ]
            if not names:
                raise UnsupportedRule(f"no selections match {pattern!r}")
            values = [self.results[name] for name in names]
            return any(values) if token == "1" else all(values)
        if token not in self.results:
            raise UnsupportedRule(f"condition references unknown selection {token!r}")
        return self.results[token]


def rule_matches(rule: dict, event: dict) -> bool:
    """Return True if the Sigma rule fires on the event."""
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise UnsupportedRule("rule has no detection block")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise UnsupportedRule("only a single string condition is supported")
    lowered = {str(key).lower(): value for key, value in event.items()}
    results = {
        name: _eval_selection(lowered, selection)
        for name, selection in detection.items()
        if name not in ("condition", "timeframe")
    }
    return _ConditionParser(condition, results).parse()
