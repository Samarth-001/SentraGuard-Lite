"""
The Detector contract.

Every detector — prompt injection, PII, RAG injection, and anything added
later — implements this protocol. Nothing else in the system (analyzer,
registry, API routes) needs to know how a detector works internally; they
only rely on this shape.

Why a Protocol instead of an ABC:
- Structural typing means detectors don't need to inherit from a shared base
  class, which keeps them decoupled from this module at runtime.
- `runtime_checkable` lets the registry assert `isinstance(obj, Detector)`
  as a cheap sanity check when detectors are registered, without forcing
  inheritance.

Adding a new detector later is exactly:
    1. Write a class with a `name` attribute and a `scan(text) -> DetectorResult` method.
    2. Register an instance of it in registry.py.
Nothing in analyzer.py, policy_engine.py, or main.py needs to change.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.models import DetectorResult


@runtime_checkable
class Detector(Protocol):
    """Structural interface every detector must satisfy."""

    #: Short, stable identifier for this detector (e.g. "prompt_injection").
    #: Used as the `tag` on the DetectorResult it produces, and as the key
    #: referenced in policy.yaml's `detectors` / `scores` sections.
    name: str

    def scan(self, text: str) -> DetectorResult:
        """
        Analyze `text` and return a DetectorResult.

        Contract:
        - Must be a pure function of `text` — no I/O, no reliance on request
          objects, no knowledge of policy thresholds or other detectors.
        - Must be deterministic: same input -> same output, every time.
        - Must not raise on malformed/empty input; return a non-matching
          DetectorResult instead (matched=False, score=0).
        - `evidence` entries must be generic and redaction-safe — never the
          raw matched substring if it could itself be sensitive (e.g. don't
          echo back a full email address or an entire injected payload).
        """
        ...


class BaseTextDetector:
    """
    Optional convenience base class for detectors that just need a `name`
    and want a default constructor. Not required — any class satisfying the
    Detector protocol works — but reduces boilerplate for the common case.
    """

    name: str = "base_text_detector"

    def scan(self, text: str) -> DetectorResult:  # pragma: no cover
        raise NotImplementedError("Subclasses must implement scan().")