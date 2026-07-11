"""
Scoring + decision logic. Pure functions only — no I/O, no policy loading
(that's config.py's job), no knowledge of FastAPI or detectors' internals
beyond the DetectorResult contract.

Pipeline (see analyzer.py for orchestration):
    1. apply_weights()      — per-result: raw score x context weight x user weight
    2. combine_score()      — across all weighted results: max() + 0.25*rest, capped at 100
    3. check_compound_rules() — tag-combination override, checked before threshold decide()
    4. decide()              — numeric threshold fallback if no compound rule fired

Combination strategy in combine_score (deliberate choice, not an accident
of sum()):
    score = max(scores) + 0.25 * sum(remaining matched scores), capped at 100

Why not naive sum-capped-at-100:
    Two low-severity PII hits (20 + 20) would hit TRANSFORM (>=40) even
    though neither signal alone is meaningfully risky. Naive summation
    punishes verbosity, not risk.

Why max() + small additive bumps instead of pure max():
    A single prompt-injection hit (70) should already dominate the score,
    but a corroborating rag_injection hit (60) alongside it is worth a
    nudge upward rather than being discarded entirely. The 0.25 weight is
    a starting point — tune it once you have real traffic/false-positive
    data. Document any retuning here.
"""

from typing import Literal

from app.config import CompoundRule, Thresholds, Weights
from app.models import DetectorResult

CORROBORATION_WEIGHT = 0.25


def apply_weights(
    result: DetectorResult,
    *,
    weights: Weights,
    user_role: str,
    source: str | None = None,
) -> DetectorResult:
    """
    Multiply a detector's raw score by user-role and context/source
    weights, capped at 100.

    - `source` should be "prompt" for the top-level user prompt, or
      ContextDoc.source (e.g. "trusted_document", "external_pdf") for RAG
      context docs.
    - Unmatched results (score=0) pass through untouched — 0 x anything is
      still 0, and reweighting a non-match has no meaning.
    - Only `score` changes; tag/matched/evidence/sanitized_text are
      preserved so downstream sanitization and tag collection still work.
    """
    if not result.matched:
        return result

    user_weight = weights.user_role.get(user_role, weights.user_role.get("default", 1.0))
    context_weight = weights.context.get(source or "prompt", weights.context.get("default", 1.0))

    weighted_score = round(result.score * user_weight * context_weight)
    weighted_score = max(0, min(100, weighted_score))

    return result.model_copy(update={"score": weighted_score})


def combine_score(results: list[DetectorResult]) -> int:
    """
    Combine (already-weighted) detector results into a single 0-100 risk
    score. Order-independent by construction (sorts before combining).
    """
    matched_scores = sorted(
        (r.score for r in results if r.matched),
        reverse=True,
    )
    if not matched_scores:
        return 0

    top_score, *rest = matched_scores
    bump = sum(int(s * CORROBORATION_WEIGHT) for s in rest)
    return min(100, top_score + bump)


def check_compound_rules(
    results: list[DetectorResult],
    compound_rules: list[CompoundRule],
) -> Literal["block", "transform"] | None:
    """
    Tag-combination check, evaluated before the numeric threshold decide().
    Rules are checked in the order they appear in policy.yaml; the first
    rule whose full tag set is a subset of the matched tags wins.

    Returns the rule's action, or None if no compound rule fired (in which
    case the caller should fall back to decide()).
    """
    matched_tags = {r.tag for r in results if r.matched}
    for rule in compound_rules:
        if set(rule.tags).issubset(matched_tags):
            return rule.action
    return None


def decide(score: int, thresholds: Thresholds) -> Literal["allow", "block", "transform"]:
    """
    Threshold check. block_score and transform_score are both inclusive
    lower bounds — a score exactly equal to a threshold triggers that
    action.
    """
    if score >= thresholds.block_score:
        return "block"
    if score >= thresholds.transform_score:
        return "transform"
    return "allow"