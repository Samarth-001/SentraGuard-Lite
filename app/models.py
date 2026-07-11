"""
Domain models for SentraGuard Lite.

These are the contracts every other module depends on. Detectors, the policy
engine, the analyzer, and the API routes all speak in terms of these types —
nothing downstream should invent its own ad-hoc dict shape.

Design notes:
- `DetectorResult` is the universal output of every detector (see
  detectors/base.py for the Detector protocol). Every current and future
  detector — prompt injection, PII, RAG injection, and anything added later
  (credit cards, secrets, toxicity, ...) — returns exactly this shape.
- `evidence` strings must never contain the raw sensitive value that was
  matched (e.g. an actual email address or the full injected payload).
  Detectors are responsible for keeping evidence generic/redacted-safe;
  this is enforced by convention and by unit tests, not by the type system.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request-side models
# ---------------------------------------------------------------------------

class ContextDoc(BaseModel):
    """A single retrieved document passed alongside the prompt (RAG context)."""

    id: str
    text: str
    # Trust classification used for context-weighted scoring, e.g.
    # "trusted_document", "internal_wiki", "external_pdf". Falls back to
    # policy.weights.context["default"] if unrecognized.
    source: str = "default"


class Metadata(BaseModel):
    """Caller-supplied metadata. Used for tracing/logging/policy routing,
    never fed directly into detector scan() calls."""

    app_id: str
    user_id: str
    request_id: str
    # Which policy (policy/tenants/{tenant_id}.yaml) applies to this request.
    tenant_id: str = "default"
    # Drives user-weighted scoring, e.g. "admin", "trusted", "anonymous".
    user_role: str = "default"


class AnalyzeRequest(BaseModel):
    """Body of POST /analyze."""

    prompt: str
    context_docs: List[ContextDoc] = Field(default_factory=list)
    metadata: Metadata


# ---------------------------------------------------------------------------
# Detector output — the universal contract between detectors and everything
# downstream of them (analyzer, policy engine).
# ---------------------------------------------------------------------------

class DetectorResult(BaseModel):
    """
    What every detector returns from `scan()`.

    - `matched`: did this detector find anything at all?
    - `score`: this detector's own contribution to risk (0-100), independent
      of any other detector. Combining scores across detectors is the policy
      engine's job, not the detector's.
    - `evidence`: short, generic, human-readable strings. Never the raw
      matched value itself (no literal email addresses, no full injected
      prompt text) — these end up in API responses and logs.
    - `sanitized_text`: only set by detectors that redact/clean text (PII,
      RAG injection). Detectors that only detect (e.g. prompt injection on
      the main prompt) can leave this as None.
    """

    tag: str
    matched: bool
    score: int = Field(ge=0, le=100)
    evidence: List[str] = Field(default_factory=list)
    sanitized_text: Optional[str] = None


# ---------------------------------------------------------------------------
# Response-side models
# ---------------------------------------------------------------------------

class Reason(BaseModel):
    """One entry in AnalyzeResponse.reasons — a matched detector's explanation."""

    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    """Body of the POST /analyze response."""

    decision: Literal["allow", "block", "transform"]
    risk_score: int = Field(ge=0, le=100)
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Reason]


# ---------------------------------------------------------------------------
# Policy / config models — backs GET /policy
# ---------------------------------------------------------------------------

class Thresholds(BaseModel):
    block_score: int = Field(ge=0, le=100)
    transform_score: int = Field(ge=0, le=100)


class PolicyResponse(BaseModel):
    """Body of the GET /policy response — mirrors policy.yaml verbatim."""

    version: str
    detectors: List[str]
    thresholds: Thresholds