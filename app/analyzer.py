"""
Orchestration only: run detectors -> hand results to policy_engine -> build
the response. Zero regex, zero thresholds, zero scoring math belongs here —
if you're tempted to write `if score > 80` in this file, it belongs in
policy_engine.py instead.
"""

from app.detectors.base import DetectorResult
from app.models import AnalyzeRequest, AnalyzeResponse, ContextDoc, Reason
from app.policy_engine import combine_score, decide
from app.registry import DetectorRegistry


def analyze(request: AnalyzeRequest, registry: DetectorRegistry) -> AnalyzeResponse:
    # Checks the PII and the Prompt Injections
    prompt_results: list[DetectorResult] = [
        d.scan(request.prompt) for d in registry.detectors
    ]
    
    # Analyzes the RAG
    # Keep (doc_id, result) pairs so sanitization can be mapped back per-doc.
    doc_results: list[tuple[str, DetectorResult]] = [
        (doc.id, d.scan(doc.text))
        for doc in request.context_docs
        for d in registry.doc_detectors
    ]

    all_results = prompt_results + [result for _, result in doc_results]

    score = combine_score(all_results)
    decision = decide(score, registry.thresholds)

    return AnalyzeResponse(
        decision=decision,
        risk_score=score,
        risk_tags=_collect_risk_tags(all_results),
        sanitized_prompt=_sanitize_prompt(request.prompt, prompt_results),
        sanitized_context_docs=_sanitize_context_docs(request.context_docs, doc_results),
        reasons=_collect_reasons(all_results),
    )


def _collect_risk_tags(results: list[DetectorResult]) -> list[str]:
    # Sorted set, not insertion order -> deterministic regardless of
    # detector registration order (mirrors the policy engine's guarantee).
    return sorted({r.tag for r in results if r.matched})


def _collect_reasons(results: list[DetectorResult]) -> list[Reason]:
    return [
        Reason(
            tag=r.tag,
            evidence="; ".join(r.evidence) if r.evidence else f"{r.tag} matched",
        )
        for r in results
        if r.matched
    ]


def _sanitize_prompt(original: str, results: list[DetectorResult]) -> str:
    """
    If multiple detectors set sanitized_text (e.g. PII redacts, something
    else redacts too), apply them in registry order so later redactions
    build on earlier ones rather than clobbering them silently.
    """
    text = original
    for r in results:
        if r.sanitized_text is not None:
            text = r.sanitized_text
    return text


def _sanitize_context_docs(
    context_docs: list[ContextDoc],
    doc_results: list[tuple[str, DetectorResult]],
) -> list[ContextDoc]:
    sanitized_by_id: dict[str, str] = {}
    for doc_id, result in doc_results:
        if result.sanitized_text is not None:
            sanitized_by_id[doc_id] = result.sanitized_text

    return [
        ContextDoc(id=doc.id, text=sanitized_by_id.get(doc.id, doc.text))
        for doc in context_docs
    ]