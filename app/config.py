"""
Loads policy YAML (default + per-tenant overrides) into validated config
objects, with in-memory hot reload keyed on file mtime.

Deliberately kept separate from policy_engine.py: this module owns *loading*
(file I/O, env vars, tenant resolution, reload), policy_engine.py owns
*decision logic* (pure functions). Nothing in here does scoring math;
nothing in policy_engine.py touches disk.
"""

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

DEFAULT_POLICY_DIR = "policy"
DEFAULT_POLICY_DIR = Path(__file__).resolve().parent / "policy"


class Thresholds(BaseModel):
    # Aliased so policy.yaml can use the shorter "block"/"transform" keys
    # (per the design sketch) while the rest of the codebase keeps the more
    # explicit block_score/transform_score attribute names.
    block_score: int = Field(alias="block")
    transform_score: int = Field(alias="transform")

    model_config = {"populate_by_name": True}


class Weights(BaseModel):
    """
    Multipliers applied to a detector's raw score before it enters
    combine_score(). All three dicts fall back to their own "default" key,
    then to 1.0, if a specific role/source isn't listed.

    - detectors: informational base scores per detector tag (documentation/
      audit purposes — detectors already return their own score; this is
      NOT re-applied on top of it, see policy_engine.apply_weights).
    - context: keyed by ContextDoc.source (e.g. "trusted_document",
      "external_pdf", "internal_wiki") plus the special key "prompt" for
      the top-level user prompt itself.
    - user_role: keyed by Metadata.user_role (e.g. "admin", "anonymous").
    """

    detectors: dict[str, float] = Field(default_factory=dict)
    context: dict[str, float] = Field(default_factory=dict)
    user_role: dict[str, float] = Field(default_factory=dict)


class CompoundRule(BaseModel):
    """
    Tag-combination override. If every tag in `tags` is present among the
    matched detector results, `action` fires regardless of numeric score —
    see policy_engine.check_compound_rules().
    """

    tags: list[str]
    action: Literal["block", "transform"]


class PolicyConfig(BaseModel):
    version: str
    tenant_id: str = "default"
    detectors: list[str]
    scores: dict[str, int] = Field(default_factory=dict)  # kept for backward compat; currently informational only
    thresholds: Thresholds
    weights: Weights = Field(default_factory=Weights)
    compound_rules: list[CompoundRule] = Field(default_factory=list)


def get_policy_dir() -> Path:
    """Policy directory location: env var override, else repo-root default."""
    return Path(os.getenv("POLICY_DIR", DEFAULT_POLICY_DIR))


def _load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` onto `base`. Dict values merge key-by-key;
    everything else (scalars, lists) is replaced wholesale by the override."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_policy(tenant_id: str = "default", policy_dir: str | Path | None = None) -> PolicyConfig:
    """
    Load default.yaml, then deep-merge policy/tenants/{tenant_id}.yaml onto
    it if that file exists. Raises FileNotFoundError / pydantic
    ValidationError on malformed config rather than silently defaulting —
    a bad policy file should fail loudly, not at request time.
    """
    base_dir = Path(policy_dir) if policy_dir is not None else get_policy_dir()

    raw = _load_yaml(base_dir / "default.yaml")

    if tenant_id and tenant_id != "default":
        tenant_path = base_dir / "tenants" / f"{tenant_id}.yaml"
        if tenant_path.exists():
            raw = _deep_merge(raw, _load_yaml(tenant_path))
        # Unknown tenant_id -> silently falls back to default policy.
        # If you'd rather 400 on unknown tenants, check `known_tenants()`
        # at the API layer before calling load_policy().

    raw["tenant_id"] = tenant_id
    return PolicyConfig(**raw)


class PolicyLoader:
    """
    In-memory cache of PolicyConfig per tenant, invalidated by file mtime.
    No docker restart required to roll out a threshold or compound-rule
    change — edit the YAML, next request picks it up.

    Cost: one stat() per relevant file per request (cheap). If detector
    volume gets high enough that even this matters, swap to a `watchdog`
    observer that invalidates `_cache` on filesystem events instead of
    checking on every request.
    """

    def __init__(self, policy_dir: str | Path | None = None):
        self._policy_dir = Path(policy_dir) if policy_dir is not None else get_policy_dir()
        self._cache: dict[str, PolicyConfig] = {}
        self._mtimes: dict[str, float] = {}

    def _paths_for(self, tenant_id: str) -> list[Path]:
        paths = [self._policy_dir / "default.yaml"]
        if tenant_id != "default":
            paths.append(self._policy_dir / "tenants" / f"{tenant_id}.yaml")
        return paths

    def _mtime_fingerprint(self, tenant_id: str) -> float:
        return sum(p.stat().st_mtime for p in self._paths_for(tenant_id) if p.exists())

    def get_policy(self, tenant_id: str = "default") -> PolicyConfig:
        fingerprint = self._mtime_fingerprint(tenant_id)
        if tenant_id not in self._cache or self._mtimes.get(tenant_id) != fingerprint:
            self._cache[tenant_id] = load_policy(tenant_id, self._policy_dir)
            self._mtimes[tenant_id] = fingerprint
        return self._cache[tenant_id]

    def known_tenants(self) -> list[str]:
        tenants_dir = self._policy_dir / "tenants"
        if not tenants_dir.exists():
            return ["default"]
        return ["default"] + sorted(p.stem for p in tenants_dir.glob("*.yaml"))