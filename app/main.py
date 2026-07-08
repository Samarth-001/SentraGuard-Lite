"""
FastAPI app: route wiring only. Every route parses input, delegates to
analyzer.py / config.py, and returns — no scoring, no thresholds, no
detector logic lives here.

Dependencies (registry, policy) are wired via Depends(), not module-level
globals, so tests can override them — e.g. app.dependency_overrides to
swap in a fake registry with block_score=1, forcing the BLOCK path
without crafting an elaborate prompt.
"""

from fastapi import Depends, FastAPI

from app.analyzer import analyze
from app.config import PolicyConfig
from app.models import AnalyzeRequest, AnalyzeResponse
from app.registry import DetectorRegistry, get_registry

app = FastAPI(title="SentraGuard Lite")


def get_policy(registry: DetectorRegistry = Depends(get_registry)) -> PolicyConfig:
    return registry.policy


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_route(
    request: AnalyzeRequest,
    registry: DetectorRegistry = Depends(get_registry),
) -> AnalyzeResponse:
    # Pydantic validates the request body -> 422 on bad payload for free.
    return analyze(request, registry)


@app.get("/policy", response_model=PolicyConfig)
def policy_route(policy: PolicyConfig = Depends(get_policy)) -> PolicyConfig:
    # Returns policy.yaml verbatim (including `version`) -> real config
    # artifact, not a string embedded in route code.
    return policy


@app.get("/health")
def health_route(policy: PolicyConfig = Depends(get_policy)) -> dict[str, str]:
    # Cheap liveness check; also confirms policy.yaml loaded successfully
    # at startup. Docker HEALTHCHECK can hit this or /policy directly.
    return {"status": "ok", "policy_version": policy.version}