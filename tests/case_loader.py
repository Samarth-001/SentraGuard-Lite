from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

TESTS_DIR = Path(__file__).resolve().parent


def _to_cases(obj) -> List[dict]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        return [obj]
    return []


def load_cases(root: Path = TESTS_DIR) -> List[Tuple[str, List[str]]]:
    """Recursively scan `root` for *.json files, each holding either a
    single {"input": ..., "expected": [...]} object or a JSON array of
    them, and return (input, expected) tuples for parametrize.

    A file that fails to parse or is missing required keys is skipped
    (printed as a warning) rather than crashing collection, so one bad
    drop-in case doesn't take down the whole suite.
    """
    cases: List[Tuple[str, List[str]]] = []
    for path in sorted(root.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[case_loader] skipping {path}: bad JSON ({e})")
            continue
        for entry in _to_cases(data):
            if "input" not in entry or "expected" not in entry:
                print(f"[case_loader] skipping entry in {path}: missing input/expected")
                continue
            cases.append((entry["input"], entry["expected"]))
    return cases


def case_ids(cases: List[Tuple[str, List[str]]]) -> List[str]:
    return [f"{text[:40]!r}->{expected}" for text, expected in cases]