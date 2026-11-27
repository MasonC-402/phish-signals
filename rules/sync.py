#!/usr/bin/env python3
"""Copy the canonical rule files in rules/core/ into both packages.

rules/core/*.json is the single source of truth for declarative rules. Each
package ships its own byte-identical copy, because a published package can
only contain files from inside its own directory:

    rules/core/content.json
      -> python/src/phish_signals/rules/data/content.json
      -> typescript/src/rules/data/content.json

Edit the file under rules/core/, then run this from anywhere:

    python3 rules/sync.py           # copy
    python3 rules/sync.py --check   # exit 1 if any copy is stale (what CI does)

Both test suites also fail on a stale or orphaned copy, so forgetting to run
this shows up as a red build rather than as the two languages quietly
disagreeing.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CANONICAL = REPO / "rules" / "core"
TARGETS = [
    REPO / "python" / "src" / "phish_signals" / "rules" / "data",
    REPO / "typescript" / "src" / "rules" / "data",
]


def main(argv: list[str]) -> int:
    check = "--check" in argv
    sources = {p.name: p.read_bytes() for p in sorted(CANONICAL.glob("*.json"))}
    problems: list[str] = []

    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        for name, data in sources.items():
            dest = target / name
            if dest.exists() and dest.read_bytes() == data:
                continue
            if check:
                problems.append(f"stale: {dest.relative_to(REPO)}")
            else:
                dest.write_bytes(data)
                print(f"updated {dest.relative_to(REPO)}")
        for orphan in sorted(target.glob("*.json")):
            if orphan.name not in sources:
                if check:
                    problems.append(f"no canonical source: {orphan.relative_to(REPO)}")
                else:
                    orphan.unlink()
                    print(f"removed {orphan.relative_to(REPO)}")

    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print("Run `python3 rules/sync.py` to fix.", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
