"""Adapter YAML loader.

An adapter declares, for a framework, what the sources / sinks / sanitizers
are. The reachability engine consumes this.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path as _P
from typing import Any

import yaml


@dataclass
class PatternSpec:
    kind: str                    # decorator | call | assertion | view_function | import
    pattern: str                 # glob OR regex (see is_regex)
    is_regex: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        # Compile a matcher
        self._re: re.Pattern[str] | None = None
        self._globs: list[str] = []
        if self.is_regex:
            self._re = re.compile(self.pattern)
        elif any(ch in self.pattern for ch in "*?[]{}"):
            self._globs = _expand_braces(self.pattern)
        else:
            self._globs = [self.pattern]

    def matches(self, name: str) -> bool:
        if self._re is not None:
            return bool(self._re.search(name))
        return any(fnmatch.fnmatch(name, g) for g in self._globs)


def _expand_braces(pattern: str) -> list[str]:
    """Expand foo.{a,b,c} to [foo.a, foo.b, foo.c]. One level of braces only."""
    if "{" not in pattern:
        return [pattern]
    pre, rest = pattern.split("{", 1)
    inside, post = rest.split("}", 1)
    options = inside.split(",")
    return [pre + o + post for o in options]


@dataclass
class Adapter:
    name: str
    language: str
    version: str = "1.0"
    sources: list[PatternSpec] = field(default_factory=list)
    sinks: list[PatternSpec] = field(default_factory=list)
    sanitizers: list[PatternSpec] = field(default_factory=list)
    confidence_rules: list[dict[str, Any]] = field(default_factory=list)
    # severity weights per sink pattern (highest wins on multi-match)
    sink_weights: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, name_or_path: str) -> "Adapter":
        """Load adapter by name (searches bundled YAMLs) or by file path."""
        p = _P(name_or_path)
        if not p.exists():
            # Search bundled
            here = _P(__file__).parent
            candidate = here / f"{name_or_path}.yaml"
            if candidate.exists():
                p = candidate
            else:
                raise FileNotFoundError(f"Adapter '{name_or_path}' not found")
        with open(p) as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Adapter":
        def mk(entries: list[dict[str, Any]]) -> list[PatternSpec]:
            return [
                PatternSpec(
                    kind=e["kind"],
                    pattern=e["pattern"],
                    is_regex=e.get("is_regex", False),
                    description=e.get("description", ""),
                )
                for e in entries or []
            ]

        return cls(
            name=data["name"],
            language=data["language"],
            version=data.get("version", "1.0"),
            sources=mk(data.get("sources", [])),
            sinks=mk(data.get("sinks", [])),
            sanitizers=mk(data.get("sanitizers", [])),
            confidence_rules=data.get("confidence_rules", []),
            sink_weights=data.get("sink_weights", {}),
        )
