"""
Scoring + decision logic. Pure functions only — no I/O, no policy.yaml
loading (that's config.py's job), no knowledge of FastAPI or detectors'
internals beyond the DetectorResult contract.

Combination strategy (deliberate choice, not an accident of sum()):
    score = max(scores) + 0.25 * sum(remaining matched scores), capped at 100

Why not naive sum-capped-at-100:
    Two low-severity PII hits (20 + 20) would hit TRANSFORM (>=40) even
    though neither signal alone is meaningfully risky, and even though
    both firing is often just "two emails in one message" rather than a
    more dangerous pattern. Naive summation punishes verbosity, not risk.

Why max() + small additive bumps instead of pure max():
    A single prompt-injection hit (70) should already dominate the score,
    but if a rag_injection hit (60) *also* fires alongside it, that's a
    corroborating signal worth nudging the score up rather than ignoring
    entirely (pure max() would discard the second signal completely).
    The 0.25 weight is a starting point — tune it once you have real
    traffic/false-positive data. Document any retuning here.

Tradeoff being accepted: this is still a heuristic, not a calibrated
probability. It's tunable and testable, which is the main goal at this
stage — see DESIGN_NOTES.md for the deferred ML/embedding-based alternative.
"""

from typing import Literal

from app.config import Thresholds
from app.models import DetectorResult

CORROBORATION_WEIGHT = 0.25


def combine_score(results: list[DetectorResult]) -> int:
    """
    Combine detector results into a single 0-100 risk score.
    Order-independent by construction (sorts before combining) — see
    tests/test_policy_engine.py::test_combine_score_order_independent.
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


def decide(score: int, thresholds: Thresholds) -> Literal["allow", "block", "transform"]:
    """
    Threshold check. block_score and transform_score are both inclusive
    lower bounds — a score exactly equal to a threshold triggers that
    action (documented so boundary tests aren't ambiguous).
    """
    if score >= thresholds.block_score:
        return "block"
    if score >= thresholds.transform_score:
        return "transform"
    return "allow"