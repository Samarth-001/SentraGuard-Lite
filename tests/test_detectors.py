import pytest

from app.analyzer import analyze
from app.models import AnalyzeRequest, Metadata
from app.registry import DetectorRegistry
from tests.case_loader import load_cases, case_ids, TESTS_DIR

ALL_CASES = load_cases(TESTS_DIR)
registry = DetectorRegistry()


@pytest.mark.parametrize("text,expected", ALL_CASES, ids=case_ids(ALL_CASES))
def test_detection(text, expected):
    request = AnalyzeRequest(
        prompt=text,
        context_docs=[],
        metadata=Metadata(
            app_id="pytest",
            user_id="test-user",
            request_id="test-request",
        ),
    )

    response = analyze(request, registry)

    detected = set(response.risk_tags)

    assert detected == set(expected)