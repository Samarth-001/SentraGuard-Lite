"""
Single place wiring which detectors run against what. Adding detector #4
(e.g. credit card numbers) later = one import + one line in one of the two
lists below. Nothing in analyzer.py or main.py changes.

Detectors are split into two groups because they scan different things:
- `detectors`      -> run once against the top-level prompt
- `doc_detectors`  -> run against each context_docs[i].text independently
"""

from app.config import PolicyConfig, load_policy
from app.detectors.pii import PIIDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.rag_injection import RagInjectionDetector


class DetectorRegistry:
    def __init__(self, policy: PolicyConfig | None = None):
        self.policy = policy or load_policy()

        self.detectors = [
            PromptInjectionDetector(),
            PIIDetector(),
        ]
        self.doc_detectors = [
            RagInjectionDetector(),
        ]

    @property
    def thresholds(self):
        return self.policy.thresholds


_registry: DetectorRegistry | None = None


def get_registry() -> DetectorRegistry:
    """
    Singleton accessor. Intended to be used as a FastAPI dependency in
    main.py (step 7) via `Depends(get_registry)` — that's also the seam
    tests use to swap in a fake policy (e.g. block_score=1) to force the
    BLOCK path without crafting elaborate prompts.
    """
    global _registry
    if _registry is None:
        _registry = DetectorRegistry()
    return _registry