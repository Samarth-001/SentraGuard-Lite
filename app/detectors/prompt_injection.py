"""
Prompt injection / jailbreak heuristic detector.

Scans the raw user prompt for known injection/jailbreak phrasing
("ignore previous instructions", "act as DAN", "reveal system prompt", etc).

This is a signature/regex-based MVP, not an ML classifier. Known
limitations (documented deliberately, not accidentally):
- Only catches phrasing we've explicitly listed — novel phrasing evades it.
- No defense against obfuscation via base64/rot13 encoding, or splitting
  the phrase across multiple messages.
- Homoglyph substitution (e.g. using a Cyrillic 'а' instead of Latin 'a')
  is not normalized away; NFKC normalization only handles compatibility
  characters (full-width forms, ligatures, etc), not cross-script lookalikes.

We do normalize case, whitespace, and Unicode compatibility forms before
matching, which raises the bar slightly above a naive literal regex.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Pattern, Tuple

from app.models import DetectorResult

# (human-readable label, compiled pattern). Label is what shows up in
# `evidence` — never the raw regex source, and never the user's raw text.
_INJECTION_SIGNATURES: List[Tuple[str, Pattern]] = [
    ("ignore previous instructions", re.compile(
        r"ignore (all |any )?(the |your )?previous instructions")),
    ("disregard prior instructions", re.compile(
        r"disregard (all |any )?(the |your |prior )?instructions")),
    ("forget previous instructions", re.compile(
        r"forget (all |your |previous )?instructions")),
    ("reveal system prompt", re.compile(
        r"(reveal|show|print|repeat) (the |your )?system prompt")),
    ("act as DAN / jailbreak persona", re.compile(
        r"act as (dan\b|jailbreak)|you are now (dan\b|jailbroken|unrestricted)")),
    ("do anything now (DAN-style jailbreak)", re.compile(
        r"do anything now")),
    ("bypass safety restrictions", re.compile(
        r"bypass (your |all )?(restrictions|safety|guidelines|filters)")),
    ("override policy/rules", re.compile(
        r"override (your |the )?(policy|instructions|rules)")),
    ("developer/unrestricted mode", re.compile(
        r"developer mode|without (any )?(restrictions|rules|filters)")),
]


class PromptInjectionDetector:
    """Detector satisfying the Detector protocol (see detectors/base.py)."""

    name = "prompt_injection"

    def __init__(self, score: int = 70):
        # Score is configurable at construction time (wired from
        # policy.yaml by the registry) but the detector itself stays a
        # pure function of `text` — it doesn't read policy files.
        self.score = score

    @staticmethod
    def _normalize(text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        text = text.lower()
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(tag=self.name, matched=False, score=0)

        normalized = self._normalize(text)
        evidence = [
            f"matched known phrase: {label}"
            for label, pattern in _INJECTION_SIGNATURES
            if pattern.search(normalized)
        ]

        if not evidence:
            return DetectorResult(tag=self.name, matched=False, score=0)

        return DetectorResult(
            tag=self.name,
            matched=True,
            score=self.score,
            evidence=evidence,
        )