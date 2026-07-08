"""
PII detection + redaction detector.

Detects email addresses and phone numbers, and produces a `sanitized_text`
with matches replaced by [REDACTED_EMAIL] / [REDACTED_PHONE].

Known limitations (MVP, documented deliberately):
- Phone regex targets common US-style formats (###-###-####, with optional
  country code / parens / dots). International formats (e.g. UK, +81 with
  variable grouping) will have false negatives.
- Email regex is intentionally permissive (favors recall over precision) —
  it will occasionally match strings that aren't real emails.
- Both PII types are scored as a single flat "pii" contribution regardless
  of how many matches or types are found in one request. A production
  version might scale score with match count/type diversity; the flat
  approach is a deliberate simplicity choice for the MVP (see DESIGN_NOTES).

`evidence` never contains the raw matched value (no literal email address
or phone number) — only which pattern type matched — so the detector's own
output can't leak the PII it just found.
"""

from __future__ import annotations

import re

from app.models import DetectorResult

_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

# Matches common US-style phone formats:
#   555-123-4567, (555) 123-4567, 555.123.4567, +1 555 123 4567
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(\+?\d{1,2}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
)


class PIIDetector:
    """Detector satisfying the Detector protocol (see detectors/base.py)."""

    name = "pii"

    def __init__(self, score: int = 20):
        self.score = score

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(
                tag=self.name, matched=False, score=0, sanitized_text=text or ""
            )

        sanitized = text
        evidence = []
        matched = False

        if _EMAIL_PATTERN.search(sanitized):
            matched = True
            evidence.append("email pattern matched")
            sanitized = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", sanitized)

        if _PHONE_PATTERN.search(sanitized):
            matched = True
            evidence.append("phone number pattern matched")
            sanitized = _PHONE_PATTERN.sub("[REDACTED_PHONE]", sanitized)

        return DetectorResult(
            tag=self.name,
            matched=matched,
            score=self.score if matched else 0,
            evidence=evidence,
            sanitized_text=sanitized,
        )