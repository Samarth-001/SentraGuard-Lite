"""
Loads policy.yaml (and relevant env vars) into validated config objects.

Deliberately kept separate from policy_engine.py: this module owns *loading*
(file I/O, env vars), policy_engine.py owns *decision logic* (pure functions).
Nothing in here does scoring math; nothing in policy_engine.py touches disk.
"""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel

DEFAULT_POLICY_PATH = "policy.yaml"


class Thresholds(BaseModel):
    block_score: int
    transform_score: int


class PolicyConfig(BaseModel):
    version: str
    detectors: list[str]
    scores: dict[str, int]
    thresholds: Thresholds


def get_policy_path() -> Path:
    """Policy file location: env var override, else repo-root default."""
    return Path(os.getenv("POLICY_PATH", DEFAULT_POLICY_PATH))


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """
    Load and validate policy.yaml. Raises FileNotFoundError / pydantic
    ValidationError on malformed config rather than silently defaulting —
    a bad policy file should fail loudly at startup, not at request time.
    """
    policy_path = Path(path) if path is not None else get_policy_path()
    with open(policy_path, "r") as f:
        raw = yaml.safe_load(f)
    return PolicyConfig(**raw)