from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Tuple

from app.models import DetectorResult


# ---------------------------------------------------------------------------
# 1. Offset-preserving normalization
# ---------------------------------------------------------------------------

# Unicode format characters (zero-width space/joiner, RTL/LTR marks,
# directional isolates, BOM, soft hyphen) are all general category "Cf".
# NFKC does not remove these — they need an explicit strip step, per the
# "unicode normalization is incomplete" gap called out in review.
def _is_format_char(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf" or ch == "\u00ad"  # soft hyphen


def _strip_format_chars(text: str) -> Tuple[str, List[int]]:
    """Remove Unicode format/zero-width characters, keeping a map from
    each surviving character's new index back to its original index."""
    out_chars: List[str] = []
    out_map: List[int] = []
    for i, ch in enumerate(text):
        if _is_format_char(ch):
            continue
        out_chars.append(ch)
        out_map.append(i)
    return "".join(out_chars), out_map


def _nfkc_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    """Apply NFKC per source character (not to the whole string at once),
    expanding the offset map alongside it so every output codepoint still
    knows which original codepoint it came from — including when one
    source character (e.g. a full-width letter, a ligature) expands into
    multiple output characters."""
    out_chars: List[str] = []
    out_map: List[int] = []
    for ch, src_idx in zip(text, src_map):
        for expanded in unicodedata.normalize("NFKC", ch):
            out_chars.append(expanded)
            out_map.append(src_idx)
    return "".join(out_chars), out_map


def normalize_with_map(text: str) -> Tuple[str, List[int]]:
    """Full normalization pipeline: strip format chars -> NFKC per char.
    Returns (normalized_text, index_map) where index_map[i] is the index
    in the *original* text that normalized_text[i] came from."""
    stripped, stripped_map = _strip_format_chars(text)
    return _nfkc_with_map(stripped, stripped_map)


def _map_span_to_original(start: int, end: int, index_map: List[int], original_len: int) -> Tuple[int, int]:
    """Translate a [start, end) span in normalized-text coordinates back
    to the equivalent span in the original text."""
    if not index_map:
        return start, end
    orig_start = index_map[start] if start < len(index_map) else original_len
    if end <= start:
        return orig_start, orig_start
    last_idx = min(end, len(index_map)) - 1
    orig_end = index_map[last_idx] + 1
    return orig_start, orig_end


# ---------------------------------------------------------------------------
# 2. Structured signatures (dataclass, not bare regex tuples)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    id: str
    severity: int
    pattern: Pattern


SIGNATURES: List[Signature] = [
    Signature(
        id="system_directive",
        severity=30,
        pattern=re.compile(r"(^|\n)\s*system\s*:", re.IGNORECASE),
    ),
    Signature(
        id="policy_override",
        severity=25,
        pattern=re.compile(
            r"(override|bypass)\s+(the |your |all )?(policy|policies|rules|guidelines|restrictions|filters)",
            re.IGNORECASE,
        ),
    ),
    Signature(
        id="instruction_override",
        # Broadened per review: the original only caught the literal
        # phrases "ignore guidelines" and "ignore previous instructions".
        # This folds both into one category, plus common paraphrases
        # ("ignore ALL prior guidance", "disregard previous rules",
        # "forget your policies") that a hand-maintained exact-phrase
        # list otherwise misses one at a time.
        severity=20,
        pattern=re.compile(
            r"(ignore|disregard|forget)\s+(all |any |every )?"
            r"(the |your |prior |previous |earlier )?"
            r"(guidelines|guidance|polic(y|ies)|rules|instructions)",
            re.IGNORECASE,
        ),
    ),
    Signature(
        id="assistant_directive",
        severity=15,
        pattern=re.compile(r"(assistant|you)\s+must\s+(now\s+|always\s+)?(ignore|comply|obey)", re.IGNORECASE),
    ),
]

_ID_TO_SIGNATURE: Dict[str, Signature] = {s.id: s for s in SIGNATURES}
_MAX_SCORE = 100


# ---------------------------------------------------------------------------
# 3. Findings
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    signature_id: str
    start: int   # normalized-text coordinates until merge/redact step
    end: int
    severity: int
    dampened: bool = False


def _detect(normalized: str) -> List[Finding]:
    findings: List[Finding] = []
    for sig in SIGNATURES:
        for m in sig.pattern.finditer(normalized):
            findings.append(Finding(signature_id=sig.id, start=m.start(), end=m.end(), severity=sig.severity))
    return findings


# ---------------------------------------------------------------------------
# 4. Documentation-context dampening (false-positive reduction)
# ---------------------------------------------------------------------------
# The single highest-leverage gap called out in review: a RAG context
# document that is *documentation about prompt injection* ("to detect
# attacks, search for the phrase 'ignore previous instructions'") trips
# every one of these signatures identically to an actual embedded attack.
# We don't attempt real intent modeling — just recognize the common
# shapes (fenced/inline code, "for example"-style framing) and damp score,
# while still redacting (see module docstring on why redaction still runs).

_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_EXAMPLE_FRAMING_RE = re.compile(
    r"\b(for example|e\.g\.|such as|sample phrase|search for|for instance)\b", re.IGNORECASE
)
_DAMPENING_FACTOR = 0.3
_EXAMPLE_LOOKBACK_CHARS = 80


def _looks_like_documentation(normalized: str, start: int, end: int) -> bool:
    for fence in _CODE_FENCE_RE.finditer(normalized):
        if fence.start() <= start and end <= fence.end():
            return True
    for fence in _INLINE_CODE_RE.finditer(normalized):
        if fence.start() <= start and end <= fence.end():
            return True
    lookback = normalized[max(0, start - _EXAMPLE_LOOKBACK_CHARS):start]
    if _EXAMPLE_FRAMING_RE.search(lookback):
        return True
    return False


# ---------------------------------------------------------------------------
# 5. Merge overlapping findings (normalized-text coordinates)
# ---------------------------------------------------------------------------

def _merge_overlaps(findings: List[Finding]) -> List[Finding]:
    """Detect everything first, then merge overlapping spans into their
    union (highest severity wins the label) before redacting once — the
    same ordering-bug fix applied to the PII detector: sequential
    `pattern.sub()` calls risk one signature's replacement shifting
    offsets or creating a spurious match for the next one."""
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: f.start)
    merged: List[Finding] = [ordered[0]]
    for f in ordered[1:]:
        last = merged[-1]
        if f.start < last.end:
            winner = last if last.severity >= f.severity else f
            merged[-1] = Finding(
                signature_id=winner.signature_id,
                start=min(last.start, f.start),
                end=max(last.end, f.end),
                severity=winner.severity,
                dampened=last.dampened or f.dampened,
            )
        else:
            merged.append(f)
    return merged


# ---------------------------------------------------------------------------
# 6. Redaction — single pass over the ORIGINAL text, using spans mapped
#    back from normalized-text coordinates. This is the actual fix for
#    the detect/redact mismatch bug.
# ---------------------------------------------------------------------------

_REDACTION_TOKEN = "[REDACTED_INSTRUCTION]"


def _redact(original: str, findings: List[Finding], index_map: List[int]) -> str:
    if not findings:
        return original
    pieces: List[str] = []
    cursor = 0
    for f in findings:
        orig_start, orig_end = _map_span_to_original(f.start, f.end, index_map, len(original))
        if orig_start < cursor:
            continue  # overlap already covered by a previous mapped span
        pieces.append(original[cursor:orig_start])
        pieces.append(_REDACTION_TOKEN)
        cursor = orig_end
    pieces.append(original[cursor:])
    return "".join(pieces)


# ---------------------------------------------------------------------------
# 7. Score — sum of distinct-signature severities (dampened where the
#    match reads as documentation), capped, instead of a flat constant.
# ---------------------------------------------------------------------------

def _score(findings: List[Finding]) -> int:
    if not findings:
        return 0
    by_signature: Dict[str, int] = {}
    for f in findings:
        contribution = int(f.severity * _DAMPENING_FACTOR) if f.dampened else f.severity
        by_signature[f.signature_id] = max(by_signature.get(f.signature_id, 0), contribution)
    return min(sum(by_signature.values()), _MAX_SCORE)


# ---------------------------------------------------------------------------
# 8. Detector
# ---------------------------------------------------------------------------

class RagInjectionDetector:
    """Detector satisfying the Detector protocol (see detectors/base.py).

    Entry point (`scan`) and constructor signature are unchanged so
    existing wiring (registry / policy.yaml) keeps working unmodified.
    """

    name = "rag_injection"

    def __init__(self, score: int = 60):
        # Kept for constructor compatibility with existing call sites.
        # Scoring is now computed per-signature via `_score()`; this
        # value is used only as an unreachable-in-practice safety net.
        self.score = score

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(tag=self.name, matched=False, score=0, sanitized_text=text or "")

        normalized, index_map = normalize_with_map(text)

        findings = _detect(normalized)
        if not findings:
            return DetectorResult(tag=self.name, matched=False, score=0, sanitized_text=text)

        # -- dampen findings that read as documentation/examples --
        findings = [
            Finding(f.signature_id, f.start, f.end, f.severity,
                    dampened=_looks_like_documentation(normalized, f.start, f.end))
            for f in findings
        ]

        merged = _merge_overlaps(findings)

        # -- redact once, over the ORIGINAL text, via the offset map --
        sanitized = _redact(text, merged, index_map)

        score = _score(merged) or self.score

        evidence = [
            f"signature={f.signature_id} severity={f.severity} "
            f"span={_map_span_to_original(f.start, f.end, index_map, len(text))} "
            f"dampened={f.dampened}"
            for f in merged
        ]

        return DetectorResult(
            tag=self.name,
            matched=True,
            score=score,
            evidence=evidence,
            sanitized_text=sanitized,
        )