from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Tuple

from app.models import DetectorResult
from app.detectors.prompt_injection import (
    CATEGORIES as _PROMPT_CATEGORIES,
    _MULTILINGUAL_KEYWORDS,
    _EMBEDDED_BLOCK_PATTERNS,
    _STRUCTURAL_PATTERNS,
    _BASE64_RE,
    _HEX_BLOB_RE,
    _ROT13_HINT_RE,
    _LONG_TOKEN_RE,
    _ENTROPY_THRESHOLD,
    _shannon_entropy,
    _URL_RE,
    _URL_INSTRUCTION_CONTEXT_RE,
    _IMPERATIVE_VERBS_RE,
    _HOMOGLYPHS,
    _SPACED_LETTERS_RE,
    _LEET_MAP,
    _sequence_chain_hit,
    _role_transition_hit,
    _contradiction_hit,
    _context_window_stuffing_hit,
    _evasion_counts,
)

# ---------------------------------------------------------------------------
# Design note
# ---------------------------------------------------------------------------
# This detector used to carry its own small, independently-maintained
# signature list (4 patterns) while PromptInjectionDetector carried ~90
# features covering the same intent categories plus embedded instructions,
# multilingual keywords, entropy, URLs, sequencing, role-spoofing, etc.
# That split meant every improvement to one detector silently didn't apply
# to the other, and RAG documents in particular are the *more* dangerous
# surface for indirect/embedded injection (OWASP's classic case), so they
# deserve at least the same coverage as the raw prompt.
#
# Rather than re-scanning the document with a second, separate
# PromptInjectionDetector instance (which would give us detection but no
# spans to redact), this module imports the *building blocks* — the
# category/pattern tables and the non-span "document-level" signal
# functions — from prompt_injection.py directly, so both detectors share
# one rule set. What stays local to this file is exactly the RAG-specific
# part: offset-preserving normalization and single-pass redaction over the
# original document text, plus a couple of RAG-flavored signatures
# (system_directive / policy_override / assistant_directive) that don't
# have a natural prompt-side equivalent.


# ---------------------------------------------------------------------------
# 1. Offset-preserving normalization
# ---------------------------------------------------------------------------
# Unicode format characters (zero-width space/joiner, RTL/LTR marks,
# directional isolates, BOM, soft hyphen) are all general category "Cf".
# NFKC does not remove these — they need an explicit strip step. On top of
# that we fold homoglyphs, lowercase, and collapse spaced-letter evasion
# ("i g n o r e") the same way PromptInjectionDetector.normalize() does —
# previously this file skipped all of that, which is why obfuscated
# variants slipped through RAG documents but not raw prompts.

def _is_format_char(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf" or ch == "\u00ad"  # soft hyphen


def _strip_format_chars(text: str) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    out_map: List[int] = []
    for i, ch in enumerate(text):
        if _is_format_char(ch):
            continue
        out_chars.append(ch)
        out_map.append(i)
    return "".join(out_chars), out_map


def _nfkc_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    out_map: List[int] = []
    for ch, src_idx in zip(text, src_map):
        for expanded in unicodedata.normalize("NFKC", ch):
            out_chars.append(expanded)
            out_map.append(src_idx)
    return "".join(out_chars), out_map


def _homoglyph_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    out_map: List[int] = []
    for ch, src_idx in zip(text, src_map):
        out_chars.append(_HOMOGLYPHS.get(ch, ch))
        out_map.append(src_idx)
    return "".join(out_chars), out_map


def _lower_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    out_map: List[int] = []
    for ch, src_idx in zip(text, src_map):
        for lowered in ch.lower():
            out_chars.append(lowered)
            out_map.append(src_idx)
    return "".join(out_chars), out_map


def _collapse_spaced_letters_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    out_map: List[int] = []
    last_end = 0
    for m in _SPACED_LETTERS_RE.finditer(text):
        out_chars.extend(text[last_end:m.start()])
        out_map.extend(src_map[last_end:m.start()])
        for ch, idx in zip(text[m.start():m.end()], src_map[m.start():m.end()]):
            if ch != " ":
                out_chars.append(ch)
                out_map.append(idx)
        last_end = m.end()
    out_chars.extend(text[last_end:])
    out_map.extend(src_map[last_end:])
    return "".join(out_chars), out_map


def _collapse_spacetab_with_map(text: str, src_map: List[int]) -> Tuple[str, List[int]]:
    """Collapse runs of spaces/tabs to a single space (mirrors
    prompt_injection.normalize()). Deliberately leaves newlines alone so
    MULTILINE-anchored structural patterns (markdown headers, blockquotes,
    'SYSTEM:' at line-start) still line up correctly."""
    out_chars: List[str] = []
    out_map: List[int] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in (" ", "\t"):
            out_chars.append(" ")
            out_map.append(src_map[i])
            j = i + 1
            while j < n and text[j] in (" ", "\t"):
                j += 1
            i = j
        else:
            out_chars.append(ch)
            out_map.append(src_map[i])
            i += 1
    return "".join(out_chars), out_map


def normalize_with_map(text: str) -> Tuple[str, List[int]]:
    """Full pipeline: strip format chars -> NFKC -> homoglyph fold ->
    lowercase -> collapse spaced-letter evasion -> collapse space/tab runs.
    Returns (normalized_text, index_map) where index_map[i] is the index
    in the *original* text that normalized_text[i] came from."""
    stripped, m = _strip_format_chars(text)
    nfkc, m = _nfkc_with_map(stripped, m)
    homo, m = _homoglyph_with_map(nfkc, m)
    lowered, m = _lower_with_map(homo, m)
    collapsed, m = _collapse_spaced_letters_with_map(lowered, m)
    tidy, m = _collapse_spacetab_with_map(collapsed, m)
    return tidy, m


def _map_span_to_original(start: int, end: int, index_map: List[int], original_len: int) -> Tuple[int, int]:
    if not index_map:
        return start, end
    orig_start = index_map[start] if start < len(index_map) else original_len
    if end <= start:
        return orig_start, orig_start
    last_idx = min(end, len(index_map)) - 1
    orig_end = index_map[last_idx] + 1
    return orig_start, orig_end


# ---------------------------------------------------------------------------
# 2. Structured signatures — RAG-specific ones, plus every category from
#    the prompt-injection engine (single source of truth for intent
#    categories; only the container/normalization logic differs here).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    id: str
    severity: int
    pattern: re.Pattern


def _category_signatures() -> List[Signature]:
    return [
        Signature(id=category, severity=weight, pattern=pattern)
        for category, (weight, patterns, _canon_phrases) in _PROMPT_CATEGORIES.items()
        for pattern in patterns
    ]


def _structural_signatures() -> List[Signature]:
    return [Signature(id="structural_delimiter", severity=20, pattern=p) for p in _STRUCTURAL_PATTERNS]


SIGNATURES: List[Signature] = (
    [
        # RAG-flavored signatures without a clean prompt-side equivalent.
        Signature(id="system_directive", severity=30, pattern=re.compile(r"(^|\n)\s*system\s*:", re.IGNORECASE)),
        Signature(
            id="policy_override",
            severity=25,
            pattern=re.compile(
                r"(override|bypass)\s+(the |your |all )?(policy|policies|rules|guidelines|restrictions|filters)",
                re.IGNORECASE,
            ),
        ),
        Signature(
            id="assistant_directive",
            severity=15,
            pattern=re.compile(r"(assistant|you)\s+must\s+(now\s+|always\s+)?(ignore|comply|obey)", re.IGNORECASE),
        ),
    ]
    + _category_signatures()
    + _structural_signatures()
)
_MAX_SCORE = 100


# ---------------------------------------------------------------------------
# 3. Findings — all coordinates below are ORIGINAL-text coordinates. Any
#    match found in normalized/leet views is translated back to original
#    coordinates immediately, so dampening/merging/redaction/scoring only
#    ever deal with one coordinate space.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    signature_id: str
    start: int
    end: int
    severity: int
    dampened: bool = False


def _detect_signatures(normalized: str, index_map: List[int], original_len: int) -> List[Finding]:
    findings: List[Finding] = []
    leet_view = normalized.translate(_LEET_MAP)
    views = [normalized] if leet_view == normalized else [normalized, leet_view]
    for sig in SIGNATURES:
        for view in views:
            for m in sig.pattern.finditer(view):
                orig_start, orig_end = _map_span_to_original(m.start(), m.end(), index_map, original_len)
                findings.append(Finding(sig.id, orig_start, orig_end, sig.severity))
    return findings


def _detect_embedded_instructions(normalized: str, index_map: List[int], original_len: int) -> List[Finding]:
    """Indirect-injection case: a directive smuggled inside HTML comments,
    code fences, <system> tags, or fake YAML/JSON role metadata — exactly
    the pattern OWASP calls out, and exactly what a RAG document is most
    likely to carry."""
    findings: List[Finding] = []
    for pattern in _EMBEDDED_BLOCK_PATTERNS:
        for m in pattern.finditer(normalized):
            inner = m.group(1) if m.groups() else m.group(0)
            if inner and inner.strip() and _IMPERATIVE_VERBS_RE.search(inner):
                orig_start, orig_end = _map_span_to_original(m.start(), m.end(), index_map, original_len)
                findings.append(Finding("embedded_instruction", orig_start, orig_end, 40))
    return findings


def _detect_multilingual(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for phrases in _MULTILINGUAL_KEYWORDS.values():
        for phrase in phrases:
            start = 0
            while True:
                idx = text.find(phrase, start)
                if idx == -1:
                    break
                findings.append(Finding("multilingual_override", idx, idx + len(phrase), 35))
                start = idx + len(phrase)
    return findings


def _detect_url_signals(text: str) -> List[Finding]:
    findings = [
        Finding("external_instruction_source", m.start(), m.end(), 35)
        for m in _URL_INSTRUCTION_CONTEXT_RE.finditer(text)
    ]
    if not findings:
        findings = [
            Finding("external_instruction_source", m.start(), m.end(), 10)
            for m in _URL_RE.finditer(text)
        ]
    return findings


def _detect_encoded_payloads(text: str) -> List[Finding]:
    """Regex hits (base64/hex/rot13-hint) plus entropy on any long token,
    so obfuscated/encoded payloads are caught generally, not just the
    specific encodings we have regexes for."""
    findings: List[Finding] = []
    for pattern in (_BASE64_RE, _HEX_BLOB_RE, _ROT13_HINT_RE):
        findings.extend(Finding("encoded_payload", m.start(), m.end(), 20) for m in pattern.finditer(text))
    for m in _LONG_TOKEN_RE.finditer(text):
        if _shannon_entropy(m.group(0)) >= _ENTROPY_THRESHOLD:
            findings.append(Finding("encoded_payload", m.start(), m.end(), 20))
    return findings


# ---------------------------------------------------------------------------
# 4. Document-level signals (no single redactable span) — reused directly
#    from prompt_injection.py so both detectors agree on what "chained
#    imperatives" / "role spoofing" / "contradiction" / "context stuffing"
#    / "obfuscation density" mean.
# ---------------------------------------------------------------------------

def _document_level_signals(normalized: str, original: str) -> List[Tuple[str, int, str]]:
    signals: List[Tuple[str, int, str]] = []

    if _sequence_chain_hit(normalized):
        signals.append(("multi_stage_execution_chain", 30, "chained_imperatives"))

    if _role_transition_hit(original):
        signals.append(("role_transition_spoofing", 30, "multiple_role_markers"))

    if _contradiction_hit(normalized):
        signals.append(("semantic_contradiction", 25, "contradictory_verb_pair"))

    if _context_window_stuffing_hit(normalized):
        signals.append(("context_window_stuffing", 25, "filler_then_payload"))

    evasions = _evasion_counts(original)
    total = sum(evasions.values())
    if total >= 5:
        weight = 20 if total < 15 else 30
        note = (
            f"homoglyphs={evasions['homoglyph']},zero_width={evasions['zero_width']},"
            f"leet={evasions['leet_mix']},spaced={evasions['spaced_letters']}"
        )
        signals.append(("obfuscation_evasion", weight, note))

    return signals


# ---------------------------------------------------------------------------
# 5. Documentation-context dampening (false-positive reduction)
# ---------------------------------------------------------------------------
# A RAG context document that is *documentation about prompt injection*
# ("to detect attacks, search for the phrase 'ignore previous
# instructions'") trips these signatures identically to an actual embedded
# attack. We don't attempt real intent modeling — just recognize the
# common shapes (fenced/inline code, "for example"-style framing) and
# damp score, while still redacting.

_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_EXAMPLE_FRAMING_RE = re.compile(
    r"\b(for example|e\.g\.|such as|sample phrase|search for|for instance)\b", re.IGNORECASE
)
_DAMPENING_FACTOR = 0.3
_EXAMPLE_LOOKBACK_CHARS = 80


def _looks_like_documentation(text: str, start: int, end: int) -> bool:
    for fence in _CODE_FENCE_RE.finditer(text):
        if fence.start() <= start and end <= fence.end():
            return True
    for fence in _INLINE_CODE_RE.finditer(text):
        if fence.start() <= start and end <= fence.end():
            return True
    lookback = text[max(0, start - _EXAMPLE_LOOKBACK_CHARS):start]
    if _EXAMPLE_FRAMING_RE.search(lookback):
        return True
    return False


# ---------------------------------------------------------------------------
# 6. Merge overlapping findings (all in original-text coordinates now)
# ---------------------------------------------------------------------------

def _merge_overlaps(findings: List[Finding]) -> List[Finding]:
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
# 7. Redaction — single pass over the original text using already-mapped
#    original-coordinate spans.
# ---------------------------------------------------------------------------

_REDACTION_TOKEN = "[REDACTED_INSTRUCTION]"


def _redact(original: str, findings: List[Finding]) -> str:
    if not findings:
        return original
    pieces: List[str] = []
    cursor = 0
    for f in findings:
        if f.start < cursor:
            continue  # already covered by a previous span
        pieces.append(original[cursor:f.start])
        pieces.append(_REDACTION_TOKEN)
        cursor = f.end
    pieces.append(original[cursor:])
    return "".join(pieces)


# ---------------------------------------------------------------------------
# 8. Score — sum of distinct-signature severities (dampened where the
#    match reads as documentation) plus document-level signal weights,
#    capped.
# ---------------------------------------------------------------------------

def _score_findings(findings: List[Finding]) -> int:
    by_signature: Dict[str, int] = {}
    for f in findings:
        contribution = int(f.severity * _DAMPENING_FACTOR) if f.dampened else f.severity
        by_signature[f.signature_id] = max(by_signature.get(f.signature_id, 0), contribution)
    return sum(by_signature.values())


# ---------------------------------------------------------------------------
# 9. Detector
# ---------------------------------------------------------------------------

class RagInjectionDetector:
    """Detector satisfying the Detector protocol (see detectors/base.py).

    Entry point (`scan`) and constructor signature are unchanged so
    existing wiring (registry / policy.yaml) keeps working unmodified.
    """

    name = "rag_injection"

    def __init__(self, score: int = 60):
        # Kept for constructor compatibility with existing call sites.
        # Scoring is now computed per-signature via `_score_findings()`
        # plus document-level signal weights; this value is used only as
        # an unreachable-in-practice safety net.
        self.score = score

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(tag=self.name, matched=False, score=0, sanitized_text=text or "")

        normalized, index_map = normalize_with_map(text)
        original_len = len(text)

        span_findings: List[Finding] = []
        span_findings += _detect_signatures(normalized, index_map, original_len)
        span_findings += _detect_embedded_instructions(normalized, index_map, original_len)
        span_findings += _detect_multilingual(text)
        span_findings += _detect_url_signals(text)
        span_findings += _detect_encoded_payloads(text)

        doc_signals = _document_level_signals(normalized, text)

        if not span_findings and not doc_signals:
            return DetectorResult(tag=self.name, matched=False, score=0, sanitized_text=text)

        # -- dampen span findings that read as documentation/examples --
        span_findings = [
            Finding(f.signature_id, f.start, f.end, f.severity,
                    dampened=_looks_like_documentation(text, f.start, f.end))
            for f in span_findings
        ]

        merged = _merge_overlaps(span_findings)

        # -- redact once, over the original text --
        sanitized = _redact(text, merged)

        span_score = _score_findings(merged)
        doc_score = sum(weight for _, weight, _ in doc_signals)
        score = min(span_score + doc_score, _MAX_SCORE) or self.score

        evidence = [
            f"signature={f.signature_id} severity={f.severity} span=({f.start},{f.end}) dampened={f.dampened}"
            for f in merged
        ] + [
            f"signal={category} weight={weight} note={note}"
            for category, weight, note in doc_signals
        ]

        return DetectorResult(
            tag=self.name,
            matched=True,
            score=score,
            evidence=evidence,
            sanitized_text=sanitized,
        )