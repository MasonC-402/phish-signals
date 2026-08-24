"""Runs the language-neutral conformance vectors under ../../conformance/vectors
against this implementation. See ../../conformance/README.md for the vector
format and why this exists: it's what catches this implementation and the
TypeScript one silently disagreeing on what a given input means.

Unlike the TypeScript harness — the reference implementation, where every
current vector already has a matching export, so a missing function is a
real bug — this harness SKIPS a vector whose module or function isn't
implemented yet, rather than failing. The Python port is a work in
progress; "not implemented yet" and "implemented and wrong" are different
things and should not both show up as the same red X. A vector whose
function does exist but returns the wrong value still fails normally, same
as any other assertion.

Convention: vector files name modules and functions the way the TypeScript
source does (camelCase, e.g. "urlCheck" / "registrableDomain") since that's
the reference implementation. This harness converts both to snake_case
(phish_signals.url_check.registrable_domain) to look them up here — Python
modules are expected to use ordinary Python naming, not mirror TypeScript's.
Every module vectored so far happens to be a single lowercase word, where the
conversion is the identity, so this matters first for the checks layer
(urlCheck, authCheck, headerAnomalies, ...) as those vectors land.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[2] / "conformance" / "vectors"


def _camel_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _collect_cases() -> list[pytest.param]:
    cases: list[pytest.param] = []
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


@pytest.mark.parametrize(
    "module_name, func_name, args, expected", _collect_cases()
)
def test_conformance(
    module_name: str, func_name: str, args: list[object], expected: object
) -> None:
    py_module_name = _camel_to_snake(module_name)
    try:
        module = importlib.import_module(f"phish_signals.{py_module_name}")
    except ImportError as exc:
        if exc.name != f"phish_signals.{py_module_name}":
            raise
        pytest.skip(
            f"phish_signals.{py_module_name} "
            f"(conformance vector module '{module_name}') not ported yet"
        )

    py_func_name = _camel_to_snake(func_name)
    func = getattr(module, py_func_name, None)
    if func is None:
        pytest.skip(
            f"phish_signals.{py_module_name}.{py_func_name} "
            f"(conformance vector '{module_name}.{func_name}') "
            f"not implemented yet"
        )

    assert func(*args) == expected
