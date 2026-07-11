"""FastAPI app: route wiring only. Every route parses input, delegates to
analyzer.py / config.py, and returns -- no scoring, no thresholds, no
detector logic lives here.

Dependencies (registry, policy, auth, rate limiting) are wired via
Depends(), not module-level globals, so tests can override them -- e.g.
app.dependency_overrides to swap in a fake registry with block_score=1,
forcing the BLOCK path without crafting an elaborate prompt, or to swap
in a fake rate limiter that always trips, forcing the 429 path.
"""
import asyncio

from fastapi import Depends, FastAPI

from app.analyzer import analyze
from app.config import PolicyConfig
from app.detectors.prompt_injection import _SemanticClassifier
from app.detectors.rag_injection import get_default_embedding_backend
from app.middleware.auth import Principal
from app.middleware.rate_limit import enforce_rate_limit
from app.models import AnalyzeRequest, AnalyzeResponse
from app.registry import DetectorRegistry, get_registry

get_default_embedding_backend()
_SemanticClassifier()

app = FastAPI(title="SentraGuard Lite")


def get_policy(registry: DetectorRegistry = Depends(get_registry)) -> PolicyConfig:
    return registry.policy


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_route(
    request: AnalyzeRequest,
    registry: DetectorRegistry = Depends(get_registry),
    principal: Principal = Depends(enforce_rate_limit),
) -> AnalyzeResponse:
    # enforce_rate_limit resolves auth (API key or JWT -> Principal) *and*
    # enforces the per-app_id / per-user_id Redis sliding-window limits in
    # one Depends() -- unauthenticated or over-limit requests never reach
    # analyze(). Pydantic validates the request body -> 422 on bad payload
    # for free.
    #
    # analyze() runs the ML detectors synchronously (embedding backend,
    # semantic classifier -- both CPU/GPU-bound); it's offloaded to a
    # worker thread so the event loop keeps serving other requests instead
    # of blocking on one analysis. For detectors heavy enough that even a
    # thread pool saturates, replace this call with a Celery/RQ task
    # enqueue + a follow-up polling or webhook endpoint.
    return await asyncio.to_thread(analyze, request, registry)


@app.get("/policy", response_model=PolicyConfig)
async def policy_route(
    policy: PolicyConfig = Depends(get_policy),
    principal: Principal = Depends(enforce_rate_limit),
) -> PolicyConfig:
    # Returns policy.yaml verbatim (including `version`) -> real config
    # artifact, not a string embedded in route code. Still auth + rate
    # limited: policy contents (thresholds, detector toggles) are
    # sensitive enough not to leave open.
    return policy


@app.get("/health")
async def health_route(policy: PolicyConfig = Depends(get_policy)) -> dict[str, str]:
    # Deliberately unauthenticated and unrate-limited: container
    # orchestrators (Docker HEALTHCHECK, k8s liveness/readiness probes)
    # need to hit this without credentials. Cheap liveness check; also
    # confirms policy.yaml loaded successfully at startup.
    return {"status": "ok", "policy_version": policy.version}