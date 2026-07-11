from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import phonenumbers
import yaml

from app.models import DetectorResult

import re


# ---------------------------------------------------------------------------
# Pattern / config loading
# ---------------------------------------------------------------------------
# Everything that used to be a hardcoded constant in this module (email
# regex, phone region, Presidio entity map, confidence floor, redaction
# tokens, scoring weights) now lives in patterns/pii.yaml. Swapping that
# file (e.g. with an AIThreatIntel-fed one) changes detector behavior with
# no code change. Loading is fail-soft: a missing/invalid file falls back
# to the exact defaults this module shipped with, so nothing breaks if the
# file isn't present yet.

_PATTERNS_PATH = Path(
    os.environ.get(
        "PII_PATTERNS_PATH",
        str(Path(__file__).resolve().parent.parent / "patterns" / "pii.yaml"),
    )
)

_DEFAULT_PATTERNS: dict = {
    "email_regex": (
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
        r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b"
    ),
    "phone": {
        "default_region": "US",
        "max_scan_chars": 50_000,
    },
    "ner": {
        "language": "en",
        "min_confidence": 0.4,
        "max_scan_chars": 50_000,
        "entity_map": {
            "PERSON": "person",
            "LOCATION": "location",
            "CREDIT_CARD": "credit_card",
            "US_SSN": "ssn",
            "US_BANK_NUMBER": "bank_account",
            "IBAN_CODE": "iban",
            "IP_ADDRESS": "ip_address",
            "CRYPTO": "crypto_wallet",
            "US_DRIVER_LICENSE": "drivers_license",
            "US_PASSPORT": "passport",
            "MEDICAL_LICENSE": "medical_license",
            "EMAIL_ADDRESS": "email",
            "PHONE_NUMBER": "phone",
        },
    },
    "tokens": {
        "email": "[REDACTED_EMAIL]",
        "phone": "[REDACTED_PHONE]",
        "person": "[REDACTED_PERSON]",
        "location": "[REDACTED_LOCATION]",
        "credit_card": "[REDACTED_CREDIT_CARD]",
        "ssn": "[REDACTED_SSN]",
        "bank_account": "[REDACTED_BANK_ACCOUNT]",
        "iban": "[REDACTED_IBAN]",
        "ip_address": "[REDACTED_IP_ADDRESS]",
        "crypto_wallet": "[REDACTED_CRYPTO_WALLET]",
        "drivers_license": "[REDACTED_DRIVERS_LICENSE]",
        "passport": "[REDACTED_PASSPORT]",
        "medical_license": "[REDACTED_MEDICAL_LICENSE]",
    },
    "scoring": {
        "max_score": 60,
        "weights": {
            "email": 10,
            "phone": 15,
            "person": 8,
            "location": 5,
            "credit_card": 25,
            "ssn": 30,
            "bank_account": 20,
            "iban": 20,
            "ip_address": 10,
            "crypto_wallet": 15,
            "drivers_license": 20,
            "passport": 20,
            "medical_license": 15,
        },
    },
}


def _deep_merge_defaults(data: dict) -> dict:
    """Shallow-per-section merge over `_DEFAULT_PATTERNS` so a partial
    pii.yaml (e.g. one that only overrides `scoring.weights.ssn`) doesn't
    silently drop every other key. Keeps the fallback behavior predictable
    without requiring a full recursive merge implementation.
    """
    merged = {**_DEFAULT_PATTERNS, **data}

    merged["phone"] = {**_DEFAULT_PATTERNS["phone"], **(data.get("phone") or {})}

    merged["ner"] = {**_DEFAULT_PATTERNS["ner"], **(data.get("ner") or {})}
    merged["ner"]["entity_map"] = {
        **_DEFAULT_PATTERNS["ner"]["entity_map"],
        **((data.get("ner") or {}).get("entity_map") or {}),
    }

    merged["tokens"] = {**_DEFAULT_PATTERNS["tokens"], **(data.get("tokens") or {})}

    merged["scoring"] = {**_DEFAULT_PATTERNS["scoring"], **(data.get("scoring") or {})}
    merged["scoring"]["weights"] = {
        **_DEFAULT_PATTERNS["scoring"]["weights"],
        **((data.get("scoring") or {}).get("weights") or {}),
    }

    return merged


def _load_patterns() -> dict:
    try:
        with open(_PATTERNS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (FileNotFoundError, OSError, yaml.YAMLError) as exc:
        print(
            f"[PII] Could not load patterns from {_PATTERNS_PATH} ({exc}); "
            "falling back to built-in defaults"
        )
        return _DEFAULT_PATTERNS
    return _deep_merge_defaults(data)


# Loaded once at import time (module-level singleton), same lifecycle as
# the Presidio analyzer singleton below.
_PATTERNS = _load_patterns()


# ---------------------------------------------------------------------------
# Findings — internal representation. Kept separate from DetectorResult so
# detect / merge / redact / score can each work off the same structured
# data instead of re-deriving it from strings.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    type: str          # "email" | "phone" | "person" | ... (extend via _DETECTORS)
    start: int
    end: int
    confidence: float  # 0-1


# ---------------------------------------------------------------------------
# Email detection
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(_PATTERNS["email_regex"], re.IGNORECASE)


def _find_emails(text: str) -> List[Finding]:
    return [
        Finding(type="email", start=m.start(), end=m.end(), confidence=0.9)
        for m in _EMAIL_RE.finditer(text)
    ]


# ---------------------------------------------------------------------------
# Phone detection
# ---------------------------------------------------------------------------

_DEFAULT_PHONE_REGION = _PATTERNS["phone"]["default_region"]
_MAX_PHONE_SCAN_CHARS = _PATTERNS["phone"]["max_scan_chars"]


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
# NER detection (Microsoft Presidio) — second detection layer
# ---------------------------------------------------------------------------
# The regex/library detectors above are fast and precise for
# well-structured PII (emails, phone numbers) that follows a predictable
# grammar. They can't catch *unstructured* PII — names, addresses,
# national ID numbers, bank/IBAN numbers, free-text mentions of a person
# or place — because there's no regex for "this span of text is a name."
#
# Most production-grade PII systems are hybrid for exactly this reason:
#
#                 Text
#                   │
#         ┌─────────┴─────────┐
#         │                   │
#  Regex detectors       ML / NER (Presidio)
#         │                   │
#         └─────────┬─────────┘
#                   │
#              Merge findings
#                   │
#              Redact once
#
# Presidio's `AnalyzerEngine` runs a spaCy NER pipeline plus a battery of
# built-in recognizers (credit cards, SSNs, IBANs, crypto wallet
# addresses, driver's licenses, passports, etc.) and returns
# `RecognizerResult`s with an entity type, span, and confidence score —
# which maps directly onto this module's existing `Finding` shape, so it
# slots into the same detect -> merge -> redact -> score pipeline as the
# regex detectors above rather than requiring a parallel code path.
#
# We deliberately allowlist which Presidio entity types feed into
# `Finding` (below) rather than accepting all of them: broad NER over
# arbitrary text produces low-value noise for entities like DATE_TIME or
# generic NRP (nationality/religion/politics) that aren't PII in the
# redaction sense we care about here. The allowlist itself now lives in
# pii.yaml (`ner.entity_map`) rather than being hardcoded.

_PRESIDIO_ENTITY_MAP: Dict[str, str] = _PATTERNS["ner"]["entity_map"]

# Below this, Presidio's own recognizer/NER confidence is too low to act
# on for a redaction use case (as opposed to, say, a review-queue use
# case where low-confidence hints are still useful).
_PRESIDIO_MIN_CONFIDENCE = _PATTERNS["ner"]["min_confidence"]

_PRESIDIO_LANGUAGE = _PATTERNS["ner"]["language"]
_MAX_NER_SCAN_CHARS = _PATTERNS["ner"]["max_scan_chars"]


class _PresidioNER:
    """Thin, fail-soft wrapper around Presidio's `AnalyzerEngine`.

    Design mirrors the semantic-classifier wrapper used elsewhere in this
    detector suite:
      - Lazily loaded on first use, so importing this module (and every
        request that only hits the regex detectors) never pays spaCy's
        model-load cost.
      - Never raises: if `presidio-analyzer`/`spacy` aren't installed, or
        the spaCy model isn't downloaded, `available` is False and
        `analyze()` returns an empty list, so the detector degrades to
        regex-only rather than crashing the request path.
    """

    def __init__(self):
        self._analyzer = None
        self._loaded = False
        self._load_error: Optional[str] = None

    def _lazy_load(self) -> None:
        # if self._loaded:
        #     return
        self._loaded = True
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore

            print("[PII] Loading Microsoft Presidio...")
            self._analyzer = AnalyzerEngine()
            print("[PII] ✓ Microsoft Presidio loaded successfully")

        except Exception as exc:  # pragma: no cover - environment dependent
            # Missing package, missing spaCy model
            # (`python -m spacy download en_core_web_lg`), unsupported
            # environment, etc. Any of these should degrade to "NER layer
            # unavailable," never crash the request path.
            print(str(exc))
            print("NER Unavailable at this time")
            self._analyzer = None
            self._load_error = str(exc)

    @property
    def available(self) -> bool:
        self._lazy_load()
        return self._analyzer is not None

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def analyze(self, text: str):
        print("in here")
        self._lazy_load()
        print("out of here")
        if self._analyzer is None or not text:
            return []
        try:
            return self._analyzer.analyze(text=text, language=_PRESIDIO_LANGUAGE)
        except Exception:  # pragma: no cover - defensive against runtime errors
            return []


# Module-level singleton so the (potentially expensive) spaCy/NER model
# load happens at most once per process, on first actual use.
_presidio_ner = _PresidioNER()


def _find_ner_entities(text: str) -> List[Finding]:
    print("[PII] Running Presidio NER detector...")
    scan_text = text[:_MAX_NER_SCAN_CHARS]
    results = _presidio_ner.analyze(scan_text)
    print(f"[PII] Presidio returned {len(results)} entities")
    findings: List[Finding] = []
    for r in results:
        mapped_type = _PRESIDIO_ENTITY_MAP.get(r.entity_type)
        if mapped_type is None:
            continue  # entity type deliberately not in our redaction allowlist
        if r.score < _PRESIDIO_MIN_CONFIDENCE:
            continue
        findings.append(
            Finding(type=mapped_type, start=r.start, end=r.end, confidence=float(r.score))
        )
    return findings


# ---------------------------------------------------------------------------
# Registry — adding a new PII type means adding one entry here, not a new
# if-branch in scan(). This is also what makes the hybrid pipeline above
# a one-line addition rather than a parallel code path: `_find_ner_entities`
# is just another finder, detected against the same original text and
# merged/redacted/scored through the exact same machinery as the regex
# detectors.
# ---------------------------------------------------------------------------

_DETECTORS: List[Tuple[str, Callable[[str], List[Finding]]]] = [
    ("email", _find_emails),
    ("phone", _find_phones),
    ("presidio_ner", _find_ner_entities),
]

DEFAULT_TOKENS: Dict[str, str] = _PATTERNS["tokens"]

# Base score contribution per type, plus diminishing returns per extra
# match of the same type, capped so e.g. 100 emails in one request doesn't
# blow past everything else disproportionately. Weights for the
# NER-sourced types are set by sensitivity: national IDs / financial
# identifiers score higher than a bare name or city mention. Both weights
# and the cap now come from pii.yaml (`scoring.weights` / `scoring.max_score`).
_TYPE_BASE_WEIGHT: Dict[str, int] = _PATTERNS["scoring"]["weights"]
_MAX_SCORE = _PATTERNS["scoring"]["max_score"]


def _merge_overlaps(findings: List[Finding]) -> List[Finding]:
    """Detect everything first (across all detectors — regex *and*
    NER — against the original text), then merge overlapping spans into
    their union before redacting once. Union (not "pick one span and
    discard the other") so a partial overlap can never leave part of
    either finding un-redacted — correctness here matters more than which
    detector gets credit for the label, so we keep the higher-confidence
    detector's `type` but always redact the full combined span.

    This is also what lets the regex and NER layers safely overlap: e.g.
    Presidio's own EMAIL_ADDRESS/PHONE_NUMBER recognizers frequently catch
    the same span the regex detectors already found. Rather than special-
    casing that, overlap resolution here just picks whichever detector was
    more confident for that span and merges the rest normally.
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
    against the untouched original text sidesteps that entirely — and is
    exactly why the NER layer above returns `Finding`s against the
    original text rather than doing its own in-place redaction.
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

    Detection is now hybrid, per the standard PII-system shape:

        Text -> [regex detectors, Presidio NER] (parallel) -> merge -> redact once

    Regex detectors (email, phone) stay fast and precise for structured
    PII. The Presidio NER layer adds recognition of unstructured PII
    (names, locations) plus a battery of built-in recognizers for
    financial/national identifiers (credit cards, SSNs, IBANs, driver's
    licenses, passports, crypto wallet addresses, ...) that no regex list
    could reasonably cover. Both layers detect against the same original
    text and feed the same `Finding` list, so merge/redact/score logic is
    shared rather than duplicated per layer. The NER layer is fail-soft:
    if Presidio/spaCy aren't installed, this detector transparently falls
    back to regex-only behavior identical to before.

    All patterns/config (email regex, phone region, NER entity allowlist,
    confidence floor, redaction tokens, scoring weights) are loaded from
    `PII_PATTERNS_PATH` (default: patterns/pii.yaml) at import time. Swap
    that file to change detection behavior without touching this module.
    """

    name = "pii"

    def __init__(self, score: int = 20, tokens: Optional[Dict[str, str]] = None):
        # Kept for constructor compatibility with existing call sites.
        # Scoring is now computed per-match via `_score()`; this value is
        # used only as an unreachable-in-practice safety net (see scan()).
        self.score = score
        # Optional override for redaction tokens (e.g. a caller wanting
        # "[EMAIL]" instead of "[REDACTED_EMAIL]"). Defaults come from the
        # loaded pii.yaml (or built-in fallback), so no existing caller is
        # affected by this being added.
        self.tokens = {**DEFAULT_TOKENS, **(tokens or {})}

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(
                tag=self.name, matched=False, score=0, sanitized_text=text or ""
            )

        # -- detect everything first, against the original text --
        # (regex detectors and the Presidio NER layer run independently
        # and in parallel over the same original text, per the hybrid
        # pipeline described on PIIDetector.)
        findings: List[Finding] = []
        for _, finder in _DETECTORS:
            findings.extend(finder(text))

        if not findings:
            return DetectorResult(
                tag=self.name, matched=False, score=0, sanitized_text=text
            )

        findings = _merge_overlaps(findings)
        print(f"[PII] Final merged findings: {findings}")

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