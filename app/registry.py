"""
Single place wiring which detectors run against what, and which policy
(tenant-aware, hot-reloadable) backs a given request.

Detectors are split into two groups because they scan different things:
- `detectors`      -> run once against the top-level prompt
- `doc_detectors`  -> run against each context_docs[i].text independently

Policy resolution is delegated to PolicyLoader (config.py), which handles
tenant merging and mtime-based hot reload. This class just exposes it.
"""

from app.config import PolicyConfig, PolicyLoader
from app.detectors.pii import PIIDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.rag_injection import RagInjectionDetector


class DetectorRegistry:
    def __init__(self, policy_loader: PolicyLoader | None = None):
        self._policy_loader = policy_loader or PolicyLoader()

        self.detectors = [
            PromptInjectionDetector(),
            PIIDetector(),
        ]
        self.doc_detectors = [
            RagInjectionDetector(),
        ]

    def get_policy(self, tenant_id: str = "default") -> PolicyConfig:
        return self._policy_loader.get_policy(tenant_id)

    def known_tenants(self) -> list[str]:
        return self._policy_loader.known_tenants()

    @property
    def policy(self) -> PolicyConfig:
        """Default-tenant policy — backs /health and the no-arg GET /policy."""
        return self.get_policy("default")

    @property
    def thresholds(self):
        return self.policy.thresholds


_registry: DetectorRegistry | None = None


def get_registry() -> DetectorRegistry:
    """
    Singleton accessor, used as a FastAPI dependency via `Depends(get_registry)`.
    Also the seam tests use to swap in a fake PolicyLoader (e.g. pointing at
    a tmp policy dir) to force specific decisions without crafting elaborate
    prompts.
    """
    global _registry
    if _registry is None:
        _registry = DetectorRegistry()
    return _registry