"""
Structured audit logging for every /analyze decision.

Privacy rule: never log the prompt or context doc text — log SHA-256
hashes instead. This preserves the ability to correlate repeated inputs
across requests, and to hand a hash to a customer for "was this prompt of
yours blocked" investigations, without keeping a second copy of their raw
data in the logs.
"""

import hashlib
import json
import logging
import time
from typing import Any

from app.config import PolicyConfig
from app.models import AnalyzeRequest, AnalyzeResponse

logger = logging.getLogger("sentraguard.audit")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_audit_record(
    request: AnalyzeRequest,
    response: AnalyzeResponse,
    policy: PolicyConfig,
) -> dict[str, Any]:
    return {
        "request_id": request.metadata.request_id,
        "app_id": request.metadata.app_id,
        # user_id is hashed too -- it can be PII-adjacent (email, username)
        # depending on how callers populate metadata.
        "user_id_hash": _sha256(request.metadata.user_id),
        "tenant": policy.tenant_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_version": policy.version,
        "prompt_hash": _sha256(request.prompt),
        "context_doc_hashes": [_sha256(doc.text) for doc in request.context_docs],
        "score": response.risk_score,
        "decision": response.decision,
        "tags": response.risk_tags,
    }


def emit_audit_record(record: dict[str, Any]) -> None:
    # Single-line JSON -> trivially shippable to any log aggregator
    # (CloudWatch, Datadog, ELK) without a custom parser.
    logger.info(json.dumps(record, separators=(",", ":")))