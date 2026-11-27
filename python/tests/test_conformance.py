"""Runs the language-neutral conformance vectors under ../../conformance/vectors
against this implementation. See ../../conformance/README.md for the vector
format and why this exists: it's what catches this implementation and the
TypeScript one silently disagreeing on what a given input means.

A vector whose module or function can't be found FAILS, same as the
TypeScript harness. (While the port was in progress these were skipped
instead; now that it is complete, a skip would just let a renamed function
silently drop out of the conformance suite.)

Convention: vector files name modules and functions the way the TypeScript
source does (camelCase, e.g. "urlCheck" / "registrableDomain") since that's
the reference implementation. This harness converts both to snake_case
(phish_signals.url_check.registrable_domain) to look them up here — Python
modules are expected to use ordinary Python naming, not mirror TypeScript's.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[2] / "conformance" / "vectors"


def _camel_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _collect_cases() -> list[Any]:
    # pytest.param's return type (ParameterSet) is only importable from
    # pytest's private _pytest package.
    cases: list[Any] = []
    for path in sorted(VECTORS_DIR.rglob("*.json")):
        vector_file = json.loads(path.read_text(encoding="utf-8"))
        module_name = vector_file["module"]
        func_name = vector_file["function"]
        for case in vector_file["cases"]:
            # Most vectored functions take one argument, expressed as
            # "input"; a few (checkContent, ...) take more than one and use
            # "args" instead — see conformance/README.md's vector format.
            args = case["args"] if "args" in case else [case["input"]]
            cases.append(
                pytest.param(
                    module_name,
                    func_name,
                    args,
                    case["expect"],
                    id=f"{module_name}.{func_name}::{case['name']}",
                )
            )
    return cases


def _decode_arg(value: Any) -> Any:
    """Decode the vector-format ``{"$map": {...}}`` marker to a plain dict.

    The TypeScript reference takes headers as a ``Map``, which JSON cannot
    express, so vectors write ``{"$map": {...}}``; the TypeScript harness
    builds a ``Map`` from it and this one builds the dict Python takes.
    """
    if isinstance(value, list):
        return [_decode_arg(v) for v in value]
    if isinstance(value, dict):
        if list(value) == ["$map"]:
            return dict(value["$map"])
        return {k: _decode_arg(v) for k, v in value.items()}
    return value


@pytest.mark.parametrize("module_name, func_name, args, expected", _collect_cases())
def test_conformance(
    module_name: str, func_name: str, args: list[object], expected: object
) -> None:
    py_module_name = _camel_to_snake(module_name)
    module = importlib.import_module(f"phish_signals.{py_module_name}")

    py_func_name = _camel_to_snake(func_name)
    func = getattr(module, py_func_name, None)
    assert callable(func), (
        f"phish_signals.{py_module_name}.{py_func_name} (conformance vector "
        f"'{module_name}.{func_name}') is missing or not callable"
    )

    assert func(*[_decode_arg(a) for a in args]) == expected


_CANONICAL_RULES = Path(__file__).resolve().parents[2] / "rules" / "core"
_SHIPPED_RULES = (
    Path(__file__).resolve().parents[1] / "src" / "phish_signals" / "rules" / "data"
)


@pytest.mark.skipif(
    not _CANONICAL_RULES.is_dir(),
    reason="canonical rules/core not present (e.g. testing from an sdist)",
)
def test_shipped_rule_data_matches_canonical() -> None:
    """The shipped rule data is a byte-identical copy of rules/core/.

    See rules/sync.py. A stale copy would mean this package and the
    TypeScript one run different phrase lists while both claim to load the
    shared rules.
    """
    canonical = sorted(p.name for p in _CANONICAL_RULES.glob("*.json"))
    shipped = sorted(p.name for p in _SHIPPED_RULES.glob("*.json"))
    assert shipped == canonical, "file sets differ; run `python3 rules/sync.py`"
    for name in canonical:
        assert (_SHIPPED_RULES / name).read_bytes() == (
            _CANONICAL_RULES / name
        ).read_bytes(), f"{name} is stale; run `python3 rules/sync.py`"
