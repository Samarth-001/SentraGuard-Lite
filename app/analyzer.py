from app.audit import build_audit_record, emit_audit_record
from app.detectors.base import DetectorResult
from app.models import AnalyzeRequest, AnalyzeResponse, ContextDoc, Reason
from app.policy_engine import apply_weights, check_compound_rules, combine_score, decide
from app.registry import DetectorRegistry


def analyze(request: AnalyzeRequest, registry: DetectorRegistry) -> AnalyzeResponse:
    policy = registry.get_policy(request.metadata.tenant_id)
    user_role = request.metadata.user_role

    # Checks the PII and the Prompt Injections against the top-level prompt.
    # source="prompt" -> weights.context["prompt"], distinct from any
    # per-document source weighting below.
    prompt_results: list[DetectorResult] = [
        apply_weights(
            d.scan(request.prompt),
            weights=policy.weights,
            user_role=user_role,
            source="prompt",
        )
        for d in registry.detectors
    ]

    # Analyzes the RAG context docs. Keep (doc_id, result) pairs so
    # sanitization can be mapped back per-doc. Each doc's own `source`
    # (e.g. "trusted_document", "external_pdf") drives its context weight.
    doc_results: list[tuple[str, DetectorResult]] = [
        (
            doc.id,
            apply_weights(
                d.scan(doc.text),
                weights=policy.weights,
                user_role=user_role,
                source=doc.source,
            ),
        )
        for doc in request.context_docs
        for d in registry.doc_detectors
    ]

    all_results = prompt_results + [result for _, result in doc_results]

    score = combine_score(all_results)

    # Compound tag rules are a hard override: if the matched tag set
    # satisfies a rule, its action wins outright, regardless of the
    # numeric score. The score is still computed and reported (for
    # observability/audit) even when a compound rule decides the outcome.
    compound_action = check_compound_rules(all_results, policy.compound_rules)
    decision = compound_action or decide(score, policy.thresholds)

    response = AnalyzeResponse(
        decision=decision,
        risk_score=score,
        risk_tags=_collect_risk_tags(all_results),
        sanitized_prompt=_sanitize_prompt(request.prompt, prompt_results),
        sanitized_context_docs=_sanitize_context_docs(request.context_docs, doc_results),
        reasons=_collect_reasons(all_results),
    )

    emit_audit_record(build_audit_record(request, response, policy))

    return response


def _collect_risk_tags(results: list[DetectorResult]) -> list[str]:
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
        ContextDoc(id=doc.id, text=sanitized_by_id.get(doc.id, doc.text), source=doc.source)
        for doc in context_docs
    ]