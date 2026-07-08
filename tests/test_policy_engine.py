"""
Policy engine tests use only fake DetectorResults — no real detector
implementations are imported or run here. This proves decision logic is
correct independently of detection logic (see build plan section 10).
"""

import random

import pytest

from app.config import Thresholds
from app.models import DetectorResult
from app.policy_engine import combine_score, decide


def make_result(tag: str, matched: bool, score: int) -> DetectorResult:
    return DetectorResult(tag=tag, matched=matched, score=score, evidence=[])


# --- combine_score -----------------------------------------------------

def test_combine_score_no_results_is_zero():
    assert combine_score([]) == 0


def test_combine_score_no_matches_is_zero():
    results = [
        make_result("pii", False, 0),
        make_result("prompt_injection", False, 0),
    ]
    assert combine_score(results) == 0


def test_combine_score_single_match_returns_its_score():
    results = [
        make_result("prompt_injection", True, 70),
        make_result("pii", False, 0),
    ]
    assert combine_score(results) == 70


def test_combine_score_corroborating_signals_bump_not_sum():
    # Two 20-point PII hits should NOT naively sum to 40.
    results = [make_result("pii", True, 20), make_result("pii", True, 20)]
    score = combine_score(results)
    assert score == 20 + int(20 * 0.25)  # 25, not 40
    assert score < 40


def test_combine_score_dominant_signal_plus_bump():
    results = [
        make_result("prompt_injection", True, 70),
        make_result("rag_injection", True, 60),
    ]
    assert combine_score(results) == 70 + int(60 * 0.25)  # 85


def test_combine_score_capped_at_100():
    results = [
        make_result("prompt_injection", True, 90),
        make_result("rag_injection", True, 80),
        make_result("pii", True, 20),
    ]
    assert combine_score(results) == 100


def test_combine_score_ignores_non_matched_results():
    results = [
        make_result("prompt_injection", True, 70),
        make_result("pii", False, 20),  # scored but not matched -> ignored
    ]
    assert combine_score(results) == 70


def test_combine_score_is_order_independent():
    """Detector registration order must never affect the final score."""
    results = [
        make_result("prompt_injection", True, 70),
        make_result("pii", True, 20),
        make_result("rag_injection", True, 60),
    ]
    seen_scores = set()
    for _ in range(20):
        shuffled = results[:]
        random.shuffle(shuffled)
        seen_scores.add(combine_score(shuffled))
    assert len(seen_scores) == 1


# --- decide --------------------------------------------------------------

@pytest.fixture
def thresholds() -> Thresholds:
    return Thresholds(block_score=80, transform_score=40)


def test_decide_allow_below_transform_threshold(thresholds):
    assert decide(0, thresholds) == "allow"
    assert decide(39, thresholds) == "allow"


def test_decide_transform_at_lower_boundary(thresholds):
    assert decide(40, thresholds) == "transform"


def test_decide_transform_between_thresholds(thresholds):
    assert decide(60, thresholds) == "transform"


def test_decide_block_at_boundary(thresholds):
    assert decide(80, thresholds) == "block"


def test_decide_block_above_boundary(thresholds):
    assert decide(100, thresholds) == "block"