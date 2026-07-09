
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import phonenumbers

from app.models import DetectorResult

import re


# ---------------------------------------------------------------------------
# Findings — internal representation. Kept separate from DetectorResult so
# detect / merge / redact / score can each work off the same structured
# data instead of re-deriving it from strings.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    type: str          # "email" | "phone" | ... (extend via _DETECTORS)
    start: int
    end: int
    confidence: float  # 0-1


# ---------------------------------------------------------------------------
# Email detection
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b",
    re.IGNORECASE,
)


def _find_emails(text: str) -> List[Finding]:
    return [
        Finding(type="email", start=m.start(), end=m.end(), confidence=0.9)
        for m in _EMAIL_RE.finditer(text)
    ]


# ---------------------------------------------------------------------------
# Phone detection
# ---------------------------------------------------------------------------

_DEFAULT_PHONE_REGION = "US"
_MAX_PHONE_SCAN_CHARS = 50_000


def _find_phones(text: str) -> List[Finding]:
    scan_text = text[:_MAX_PHONE_SCAN_CHARS]
    # Leniency.POSSIBLE (not the library default, Leniency.VALID) is
    # deliberate: VALID rejects numbers that are correctly formatted but
    # not a real assigned number (e.g. US "555" exchange numbers, common
    # in examples/placeholders/test fixtures), which would silently stop
    # redacting exactly the kind of number this detector previously
    # caught via plain regex. For a PII redactor, "does this look like a
    # phone number" (POSSIBLE) is the right bar, not "is this routable."
    matcher = phonenumbers.PhoneNumberMatcher(
        scan_text, _DEFAULT_PHONE_REGION, leniency=phonenumbers.Leniency.POSSIBLE
    )
    return [
        Finding(type="phone", start=match.start, end=match.end, confidence=0.95)
        for match in matcher
    ]


# ---------------------------------------------------------------------------
# Registry — adding a new PII type means adding one entry here, not a new
# if-branch in scan().
# ---------------------------------------------------------------------------

_DETECTORS: List[Tuple[str, Callable[[str], List[Finding]]]] = [
    ("email", _find_emails),
    ("phone", _find_phones),
]

DEFAULT_TOKENS: Dict[str, str] = {
    "email": "[REDACTED_EMAIL]",
    "phone": "[REDACTED_PHONE]",
}

# Base score contribution per type, plus diminishing returns per extra
# match of the same type, capped so e.g. 100 emails in one request doesn't
# blow past everything else disproportionately.
_TYPE_BASE_WEIGHT: Dict[str, int] = {
    "email": 10,
    "phone": 15,
}
_MAX_SCORE = 40


def _merge_overlaps(findings: List[Finding]) -> List[Finding]:
    """Detect everything first (across all detectors, against the
    original text), then merge overlapping spans into their union before
    redacting once. Union (not "pick one span and discard the other") so
    a partial overlap can never leave part of either finding un-redacted —
    correctness here matters more than which detector gets credit for the
    label, so we keep the higher-confidence detector's `type` but always
    redact the full combined span.
    """
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: f.start)
    merged: List[Finding] = [ordered[0]]
    for f in ordered[1:]:
        last = merged[-1]
        if f.start < last.end:  # overlaps the previous finding
            winner = last if last.confidence >= f.confidence else f
            merged[-1] = Finding(
                type=winner.type,
                start=min(last.start, f.start),
                end=max(last.end, f.end),
                confidence=winner.confidence,
            )
        else:
            merged.append(f)
    return merged


def _redact(text: str, findings: List[Finding], tokens: Dict[str, str]) -> str:
    """Single pass over the *original* text using pre-computed, merged
    spans. This is what avoids the ordering bug of sequential
    `regex.sub()` calls: once you have more than one detector, an earlier
    detector's replacement can shift offsets or accidentally create a new
    match for a later detector to trip over. Working from spans computed
    against the untouched original text sidesteps that entirely.
    """
    if not findings:
        return text
    pieces = []
    cursor = 0
    for f in findings:
        pieces.append(text[cursor:f.start])
        pieces.append(tokens.get(f.type, f"[REDACTED_{f.type.upper()}]"))
        cursor = f.end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _score(findings: List[Finding]) -> int:
    if not findings:
        return 0
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.type] = counts.get(f.type, 0) + 1
    total = 0
    for ptype, count in counts.items():
        weight = _TYPE_BASE_WEIGHT.get(ptype, 10)
        total += weight + min(count - 1, 4) * (weight // 2)
    return min(total, _MAX_SCORE)


class PIIDetector:
    """Detector satisfying the Detector protocol (see detectors/base.py).

    Entry point (`scan`) and constructor signature are unchanged so
    existing wiring (registry / policy.yaml) keeps working unmodified.
    """

    name = "pii"

    def __init__(self, score: int = 20, tokens: Optional[Dict[str, str]] = None):
        # Kept for constructor compatibility with existing call sites.
        # Scoring is now computed per-match via `_score()`; this value is
        # used only as an unreachable-in-practice safety net (see scan()).
        self.score = score
        # Optional override for redaction tokens (e.g. a caller wanting
        # "[EMAIL]" instead of "[REDACTED_EMAIL]"). Defaults reproduce the
        # original tokens exactly, so no existing caller is affected by
        # this being added.
        self.tokens = {**DEFAULT_TOKENS, **(tokens or {})}

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(
                tag=self.name, matched=False, score=0, sanitized_text=text or ""
            )

        # -- detect everything first, against the original text --
        findings: List[Finding] = []
        for _, finder in _DETECTORS:
            findings.extend(finder(text))

        if not findings:
            return DetectorResult(
                tag=self.name, matched=False, score=0, sanitized_text=text
            )

        findings = _merge_overlaps(findings)

        # -- redact once, in a single pass over the original text --
        sanitized = _redact(text, findings, self.tokens)

        # -- score scales with match count/type, not a flat constant --
        score = _score(findings) or self.score

        # -- structured evidence: type + count + spans, never raw PII --
        by_type: Dict[str, List[Finding]] = {}
        for f in findings:
            by_type.setdefault(f.type, []).append(f)
        evidence = [
            f"type={ptype} count={len(fs)} spans={[(f.start, f.end) for f in fs]}"
            for ptype, fs in sorted(by_type.items())
        ]

        return DetectorResult(
            tag=self.name,
            matched=True,
            score=score,
            evidence=evidence,
            sanitized_text=sanitized,
        )