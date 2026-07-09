# SentraGuard Lite — Design Notes

This document is the detailed engineering record of *how* the system works
and *why* it was built this way — every detector feature, every scoring
decision, every tradeoff and known gap. The README tells you how to run
it; this tells you how it thinks.

> **Source coverage note:** this document is written from the actual
> source of `prompt_injection.py`, `rag_injection.py`, `pii.py`,
> `analyzer.py`, `main.py`, and `streamlit_app.py`. `policy_engine.py`,
> `config.py`, and `registry.py` were not available at the time of
> writing — anything about them below is *inferred* from how `analyzer.py`
> and `main.py` call them, and is marked as inferred rather than confirmed.

---

## Table of Contents

- [Design Notes Summary — Assumptions, Tradeoffs, Limitations, Next Steps for Production](#design-notes-summary--assumptions-tradeoffs-limitations-next-steps-for-production)

1. [Architecture recap](#1-architecture-recap)
2. [Detector: Prompt Injection](#2-detector-prompt-injection) — full feature catalog
3. [Detector: PII](#3-detector-pii) — full feature catalog
4. [Detector: RAG Injection](#4-detector-rag-injection) — full feature catalog
5. [Analyzer — orchestration details](#5-analyzer--orchestration-details)
6. [API layer](#6-api-layer)
7. [Streamlit UI](#7-streamlit-ui)
8. [Scoring & Policy Engine (inferred)](#8-scoring--policy-engine-inferred)
9. [Cross-cutting design decisions](#9-cross-cutting-design-decisions)
10. [Known limitations & production hardening roadmap](#10-known-limitations--production-hardening-roadmap)
11. [Deviations from the original spec — flagged explicitly](#11-deviations-from-the-original-spec--flagged-explicitly)

---

## Design Notes Summary — Assumptions, Tradeoffs, Limitations, Next Steps for Production

This is the deliverable-format summary the spec asks for: **assumptions,
tradeoffs, limitations, and next steps for production**, in one place.
Everything here is condensed from — and cross-referenced to — the detailed
sections below, which contain the full reasoning behind each point.

### Assumptions

- No ML model was assumed available and the system was assumed to need to
  run fully **offline and deterministically** — this is why detection is
  regex/heuristic-based rather than embedding- or classifier-based
  throughout (§2, §3, §4).
- `policy_engine.py`, `config.py`, and `registry.py` were **not available**
  when this document was written. Their behavior is *assumed/inferred*
  from how `analyzer.py` and `main.py` call them (`combine_score()`,
  `decide()`, `registry.detectors`, `registry.doc_detectors`,
  `registry.thresholds`) — see §8. This should be verified once those
  files are shared.
- Assumed `GET /policy` should reflect the **static config file**
  (`policy.yaml`) rather than dynamically-computed detector behavior,
  matching the spec's "returns the loaded policy/detectors configuration"
  wording — even though, per §9.1, that now makes it an incomplete
  picture of actual per-request scoring.
- Assumed a single global policy applies to every caller — no
  per-`app_id`/tenant policy variation, despite `metadata.app_id` being
  present on every request.
- Assumed default phone region **"US"** is an acceptable default for the
  PII detector; international formats are lower priority for this MVP (§3.3).
- Assumed the spec's example evidence string (`"matched phrase: ignore
  previous instructions"`) was illustrative of *format*, not a license to
  echo arbitrary matched user/document text back in evidence — evidence
  was kept structured and redaction-safe everywhere instead (§9.3).
- Assumed the "0–3 context documents" line in the spec was an example
  count rather than a hard UI/API limit — the implemented UI allows up to
  6 (§11). Flagged as an assumption worth confirming, not treated as
  settled.
- Assumed detector constructors should **keep their original `score`
  parameter** for backward compatibility with existing registry/
  `policy.yaml` wiring, even after scoring logic moved inside each
  detector (§9.1) — avoids a breaking change to call sites outside these
  three files.

### Tradeoffs

- **Regex/heuristics over ML** — full determinism, no external model
  dependency, fast, fully offline and unit-testable, at the cost of
  proxy-based detection rather than true semantic understanding.
- **Shared rule tables between `prompt_injection.py` and
  `rag_injection.py`** (§4.1, §9.4) — chosen after observing the two
  detectors' signature lists drift apart (RAG injection previously had 4
  patterns vs. prompt injection's much larger set). Traded full detector
  independence for a single source of truth on attack categories.
- **PII phone detection uses `Leniency.POSSIBLE`, not the library default
  `Leniency.VALID`** (§3.3) — accepts more false positives (numbers that
  look plausible but aren't real/assigned) in exchange for not silently
  missing common placeholder/test-fixture numbers like `555-xxxx`.
- **Detect-then-merge-then-redact in one pass**, instead of sequential
  `regex.sub()` per pattern (§3.6, §9.2) — more upfront complexity
  (`Finding` dataclasses, span math, index maps) in exchange for
  correctness: no offset-shifting bugs, no double-redaction, no
  accidental new matches created by an earlier substitution.
- **Fuzzy/paraphrase matching (difflib) applied only to prompts, not RAG
  documents** (§4.3) — keeps RAG injection's cost and complexity bounded,
  at the cost of narrower paraphrase coverage for embedded document
  attacks.
- **Dampening false positives by scaling score down, not suppressing
  entirely** (§2.13, §4.4) — keeps borderline content visible and
  auditable in `reasons` rather than silently hidden, at the cost of
  letting some genuinely ambiguous content through at a reduced but
  nonzero score.
- **Detector-level dynamic scoring vs. flat `policy.yaml` scores** (§9.1)
  — produces more expressive, better-calibrated per-request scores, at
  the direct cost of `policy.yaml`/`GET /policy` now describing scoring
  behavior that doesn't fully match reality. This is the single tradeoff
  in this document most in need of a deliberate resolution.
- **Assumed sum-capped-at-100 score combination** across detectors, rather
  than a max-plus-corroboration approach (§8) — simpler to reason about
  and test, at the cost of two low-severity matches potentially combining
  into a decision neither would trigger alone. Not confirmed against the
  real `policy_engine.py`.

### Limitations

Full detail in §10 — condensed here:

- Detection is heuristic/proxy-based, not semantic; a sufficiently novel
  phrasing, encoding, or language can evade any given layer.
- Homoglyph and multilingual coverage are hand-curated and intentionally
  partial, not exhaustive.
- The educational/meta-discussion false-positive dampener is shallow
  pattern matching and can both under- and over-dampen genuinely
  ambiguous content.
- Paraphrase/fuzzy matching doesn't extend to RAG documents.
- `policy.yaml`'s declared per-detector scores are stale relative to
  actual dynamic detector behavior.
- No hot-reload of policy config — a threshold change requires a restart.
- No authentication, rate limiting, or structured audit logging at the
  API layer.

### Next steps for production

1. **Resolve the `policy.yaml` / detector-score mismatch** (§9.1) — either
   expose real dynamic weight ranges via `/policy`, or make the config
   file the authoritative primary scoring path again. This is the highest-
   priority item, since it affects the accuracy of the system's own
   self-description.
2. **Confirm the inferred behavior of `policy_engine.py`, `config.py`,
   and `registry.py`** (§8) against their real source, and update this
   document's Scoring & Policy Engine section from "inferred" to
   "confirmed."
3. Add **authentication and rate limiting** at the API gateway/middleware
   layer (not inside this service).
4. Add **structured, redaction-safe audit logging** of decisions
   (decision, score, tags, request_id — never raw prompt/context text) for
   monitoring and compliance.
5. Support **policy hot-reload** (or at minimum a documented reload
   signal/endpoint) instead of requiring a full restart to pick up
   `policy.yaml` changes.
6. **Extend fuzzy/paraphrase matching to RAG documents** — currently
   prompt-only (§4.3).
7. Consider an **ML/embedding-based secondary pass** for higher-recall
   semantic matching, layered on top of (not replacing) the current
   deterministic rule engine — preserves auditability while closing the
   biggest structural gap (proxy detection vs. true understanding).
8. **Wire the Streamlit risk gauge's color bands to the live-fetched
   policy thresholds** instead of the current hardcoded 40/80 split (§11).
9. Add **input size guards** (max prompt length, max context docs, max
   per-doc size) ahead of detector execution — several signals (entropy
   scanning, fuzzy matching) scale with input size, so bounding worst-case
   latency matters before this sees production traffic.
10. **Deliberately settle the 3-vs-6 context-document UI limit** (§11) and
    align the spec, the API, and the UI on one number.
11. Expand phone-number detection beyond the default "US" region
    assumption (§3.3) if international traffic is expected.

---

## 1. Architecture recap

```
Detector (pure function: text -> DetectorResult)
        │
        ▼
Analyzer (orchestration only — runs detectors, has no scoring logic itself)
        │
        ▼
Policy Engine (combine_score + decide — pure functions, thresholds from policy.yaml)
        │
        ▼
API response
```

This held for the MVP. **It has partially evolved**: each detector now
computes its own nuanced, weighted, multi-signal score internally rather
than emitting a flat constant — see [§9.1](#91-scores-moved-from-policyyaml-into-the-detectors-themselves)
for what that means for `policy.yaml`.

---

## 2. Detector: Prompt Injection

`app/detectors/prompt_injection.py` — by far the most complex component in
the system. What started as a flat phrase-match list is now a weighted,
multi-signal risk engine. Every feature below fires independently and
contributes to an aggregate score; nothing here is "detect and stop."

### 2.1 Normalization pipeline (`normalize()`)

Applied before any pattern matching, in this order:

1. **Unicode NFKC normalization** — collapses compatibility characters
   (full-width digits, ligatures, etc.) to their canonical form.
2. **Zero-width character stripping** — removes `\u200b` (zero-width
   space), `\u200c`/`\u200d` (joiners), `\u2060` (word joiner), `\ufeff`
   (BOM), which attackers use to split up flagged words invisibly.
3. **Homoglyph folding** — maps visually-similar Cyrillic/fullwidth
   characters to their Latin/ASCII equivalents (`а`→`a`, `е`→`e`, `０`→`0`,
   etc.). Deliberately **not exhaustive** — the code comments call this an
   "unwinnable arms race" and cover only lookalikes actually observed in
   jailbreak attempts, not the full Unicode confusables table.
4. **Lowercasing.**
5. **Spaced-letter collapsing** — `"i g n o r e"` style evasion (3+ single
   letters separated by single spaces) is collapsed back into one word.
6. **Whitespace/punctuation collapsing** — runs of spaces/tabs collapse to
   one; repeated `!`/`?`/`.` collapse to one.

A **separate leetspeak-normalized view** (`_leet_normalized`) is computed
from the already-normalized text (`0`→`o`, `1`→`i`, `3`→`e`, `4`→`a`,
`5`→`s`, `7`→`t`, `@`→`a`) and used **only for matching**, never shown back
in evidence — leet substitution is too aggressive to apply universally
(it would mangle legitimate text containing numbers).

**Evasion counting** (`_evasion_counts`): separately from normalizing them
away, the detector *counts* how many homoglyphs, zero-width chars,
leet-mixed words, and spaced-letter instances appear in the raw text. A
single instance of one trick is weak signal; a pile of several together is
itself suspicious — see [§2.9](#29-obfuscationevasion-density).

### 2.2 Category-based signature system

Instead of one flat phrase list, patterns are grouped into **8 intent
categories**, each with a weight, a list of compiled regexes, and a list
of canonical phrases used for fuzzy/paraphrase matching (§2.3). A category
contributes its weight **at most once per scan**, no matter how many of
its patterns or phrases fire — this prevents one attack idea expressed
three different ways in the same message from being triple-counted.

| Category | Weight | What it catches |
|---|---|---|
| `instruction_override` | 40 | "ignore/disregard/forget previous instructions", "don't follow the prompts", "start over with new instructions" |
| `context_reset` | 35 | "reset your context/memory/state", "clear your history" |
| `role_hijack` | 45 | "act as DAN/root/admin", "you are now unrestricted", "do anything now", "pretend to be unfiltered" |
| `system_prompt_extraction` | 50 (highest weight — most direct exfiltration attempt) | "reveal/show/print/leak the system prompt", "repeat everything above", "what were your original instructions" |
| `authority_escalation` | 30 | "I am your developer/admin", "admin override", "security testing mode", "Anthropic/OpenAI told you to..." |
| `tool_abuse` | 35 | "run bash/shell", "delete all files", "read environment variables", "print API keys", "ignore tool restrictions" |
| `data_exfiltration` | 35 | "tell me your secrets", "reveal hidden memory/previous users", "what did other users ask" |
| `safety_bypass` | 30 | "bypass restrictions/safety/filters", "override policy/rules", "developer mode", "without any restrictions" |

### 2.3 Fuzzy / paraphrase matching

Each category also carries a short list of **canonical phrases** (e.g.
"forget what I said earlier", "pretend earlier instructions don't exist").
If no regex fires for a category, the detector falls back to computing a
`difflib.SequenceMatcher` similarity ratio between each canonical phrase
and a sliding window of the input text, sized to the phrase length + 3
words. A match at ratio ≥ **0.82** (`_FUZZY_THRESHOLD`, tuned conservatively
to avoid false positives) counts as a hit for that category.

This exists specifically to catch **paraphrased** injection attempts that
don't match any literal regex — "let's pretend the rules from before were
never actually written" reads very differently from "ignore previous
instructions" lexically, but scores highly on similarity to the canonical
phrase. Cost is bounded: windows are capped (`_FUZZY_MAX_WORDS = 300`) so a
very long input can't blow up matching time.

### 2.4 Multilingual keyword detection

A separate table (`_MULTILINGUAL_KEYWORDS`) covers **8 languages**
(Japanese, Chinese, Spanish, Hindi, French, German, Russian, Arabic) with
a handful of high-signal attack verbs/nouns per language ("ignore",
"forget", "reveal", "system prompt", "developer mode", etc.). This is
explicitly **not** a translator — it exists to catch the "just ask in the
target's non-English training majority language" bypass, using substring
matching (not `\b`-delimited regex, since word boundaries don't behave the
same way for CJK/Arabic scripts). A hit contributes the
`multilingual_override` signal at weight **35**.

### 2.5 Embedded / indirect instruction detection

Covers OWASP's classic **indirect prompt injection** case: a directive not
addressed to the model directly, but smuggled inside markup a naive
pipeline would pass through untouched — HTML comments, code fences, fake
`<system>` tags, fake YAML/JSON role metadata (`"role": "system", ...`),
or bare `role:` lines. The detector extracts the **content** of each such
container and re-checks *that* for imperative override language
(`_IMPERATIVE_VERBS_RE`), rather than only matching the container syntax —
an empty or benign code fence doesn't trigger this. Contributes
`embedded_instruction` at weight **40**.

### 2.6 Structural / fake-delimiter attacks

Separately from embedded-instruction *content* checks, this looks at
**structure alone**: markdown headers like `### SYSTEM`, `<system>` /
`<admin>` tags, `[INST]`/`[SYS]` tokens (Llama-style chat template
markers), blockquote lines starting with `system:`/`admin:`, and repeated
`***` separators. Contributes `structural_delimiter` at weight **20**.

### 2.7 Encoded payload detection

Four independent signals, any of which contributes `encoded_payload` at
weight **20**:
- **Base64-looking blobs** (`[A-Za-z0-9+/]{40,}={0,2}`).
- **Hex blobs** (20+ hex byte pairs).
- **ROT13 hints** — literal mentions of "rot13" in the text (catches
  someone asking the model to decode a ROT13'd instruction, not the
  encoded payload itself).
- **Shannon entropy** on any "long token" (20+ non-whitespace characters):
  tokens at or above **4.0 bits/character** are flagged as
  `high_entropy_blob`. This is the general-purpose catch-all — it fires on
  obfuscated/encoded payloads that don't match any specific regex (XOR'd
  blobs, unusual compressed encodings), since ordinary prose sits well
  below that entropy threshold.

### 2.8 URL / external-instruction-source analysis

Any URL present is a weak signal (`bare_url`, weight **10**) — links are
common in legitimate prompts. But a URL immediately preceded by an
imperative like "visit/follow/open/download/fetch/load/go to" is a much
stronger signal of an attempt to have the model treat external content as
instructions (`url_with_instruction_context`, weight **35**).

### 2.9 Multi-stage sequencing, role spoofing, and semantic contradiction

Three related "shape of the attack" signals, each looking at structure
rather than any single phrase:

- **`multi_stage_execution_chain`** (weight 30): 2+ sequence markers
  ("step 1", "first,", "then,", "finally,") **and** 2+ imperative verbs.
  A single "then" is nothing; a chain of "first... then... finally..."
  each paired with an override verb indicates a planned multi-step attack
  rather than one impulsive line.
- **`role_transition_spoofing`** (weight 30): 2+ distinct fake
  conversation-role lines (`User:`, `Assistant:`, `System:`, `Developer:`)
  appearing literally in the text — a common trick to make the model
  believe a system message already authorized something.
- **`semantic_contradiction`** (weight 25): contradictory verb pairs
  co-occurring (e.g. both "ignore" and "follow", or "forget" and
  "remember") — a rule-based proxy for override intent that doesn't
  require any specific phrase match.

### 2.10 Context-window stuffing

`context_window_stuffing` (weight 25) fires on two patterns:
- A long run of a single repeated character (16+), or an explicit
  "repeat X N times" instruction (both classic ways to burn context/attempt
  to push real instructions out of an evaluator's attention window).
- The **"huge filler, payload at the end"** shape: for inputs of 60+
  words, if imperative verbs appear in the last 20% of the text but *not*
  anywhere in the first 80%, that's the signature of someone padding a
  message with harmless filler specifically so the real instruction lands
  outside where a shallow scan (or a human skimming) would look.

### 2.11 Obfuscation/evasion density

Independent of whether any specific pattern matched, the detector counts
total evasion techniques used (§2.1's `_evasion_counts`): homoglyphs,
zero-width characters, leet-mixed words, spaced-letter instances. **5–14**
total instances contributes `obfuscation_evasion` at weight **20**; **15+**
escalates to weight **30**. The reasoning: heavy use of evasion tricks is
itself a signal independent of what's being evaded — a message doesn't
accidentally contain a dozen zero-width characters.

### 2.12 Statistical anomaly signals

A grab-bag of secondary signals, each contributing to a shared
`statistical_anomaly` weight (**15**) if any fire:
- **Imperative-verb density** — 3+ hits of verbs like ignore/forget/
  reveal/override/execute/delete/reset in the normalized text.
- **Instruction density** — imperative verbs per sentence ≥ 1.2 (a chain
  of commands packed into a few sentences is a stronger signal than the
  same verbs spread across a long, mostly-normal message).
- **Excessive ALL CAPS** — over 40% of characters uppercase in inputs
  longer than 20 characters.
- **Excessive punctuation** — 3+ consecutive `!`/`?`.
- **Markdown/XML tag abuse** — 3+ HTML/XML-style tags in the raw text.

### 2.13 False-positive dampening (educational / meta-discussion)

Called out in the code as **"the single highest-leverage guard"** in the
whole detector: a flat regex list flags *"what does 'ignore previous
instructions' mean?"* identically to an actual attempt to do it. Two
dampening paths, applied to the aggregate score after all signals are
summed:

- **Binary dampening** (`_looks_educational`): text matching a
  meta-discussion pattern ("what does/explain/define/example of ... prompt
  injection/jailbreak/system prompt") OR a quoted attack phrase followed
  by a `?` → score scaled to **30%** (floor of 1, never fully zeroed —
  still visible to enforcement, just correctly weighted lower).
- **Gradual dampening** (`_educational_hedge_strength`): if the binary
  check doesn't fire, the detector counts hedge/citation words present
  ("example", "paper", "research", "study", "documentation", "quoted").
  Each hit scales the score down further (down to a **0.4x** floor at
  4+ hits) — a soft decay rather than a single on/off switch, since
  "this paper studies prompt injection examples" reads less suspicious
  than a single stray mention of "example."

The detector explicitly does **not** attempt real intent modeling here —
this is deliberately shallow pattern recognition, not semantic
understanding, and is named as a known limitation in [§10](#10-known-limitations--production-hardening-roadmap).

### 2.14 Aggregation & severity

```
raw_score = min(sum of distinct fired-category/signal weights, 100)
raw_score = dampened (per §2.13) if applicable
severity  = "high" if raw_score >= 60 else "medium" if raw_score >= 30 else "low"
```

Every result's evidence list is prefixed with a summary line:
`severity=<level> aggregate_score=<n> categories=[...]` — so a human
reviewing the response can see the overall picture before reading
individual signal lines.

### 2.15 Constructor / backward compatibility

`PromptInjectionDetector(score: int = 70)` — the `score` parameter is kept
**purely for constructor compatibility** with existing wiring
(registry/policy.yaml). It no longer drives the output score at all; see
[§9.1](#91-scores-moved-from-policyyaml-into-the-detectors-themselves).

---

## 3. Detector: PII

`app/detectors/pii.py` — evolved from flat regex+redact into a structured,
extensible, confidence-weighted pipeline.

### 3.1 `Finding` — internal structured representation

```python
@dataclass(frozen=True)
class Finding:
    type: str          # "email" | "phone" | ...
    start: int
    end: int
    confidence: float  # 0-1
```

Detect → merge → redact → score all operate on this shared structure
instead of each re-deriving matches from strings independently. This is
what makes the overlap-merging and single-pass redaction below possible.

### 3.2 Email detection

A single, reasonably strict regex requiring proper local-part and domain
shape, case-insensitive. Confidence fixed at **0.9**.

### 3.3 Phone detection — via `phonenumbers`, not a hand-rolled regex

This is the most significant upgrade from the original MVP regex.
Uses Google's `libphonenumber` (Python port: the `phonenumbers` package)
via `PhoneNumberMatcher`, with:

- **Default region "US"** — numbers without an explicit country code are
  parsed as US numbers.
- **`Leniency.POSSIBLE`, not the library default `Leniency.VALID`.** This
  is a deliberate, explicitly-commented choice: `VALID` rejects
  correctly-formatted numbers that aren't real assigned numbers — e.g. the
  US "555" exchange, extremely common in examples, placeholders, and test
  fixtures. For a **redactor**, the right bar is "does this look like a
  phone number" (`POSSIBLE`), not "is this a real, routable number"
  (`VALID`). Using `VALID` would have silently stopped redacting exactly
  the kind of number a test suite (or a careless demo) is most likely to
  contain.
- **Scan length cap** — only the first 50,000 characters are scanned for
  phone numbers (`_MAX_PHONE_SCAN_CHARS`), a performance guard against
  pathologically long inputs.

### 3.4 Extensible detector registry

```python
_DETECTORS: List[Tuple[str, Callable[[str], List[Finding]]]] = [
    ("email", _find_emails),
    ("phone", _find_phones),
]
```

Adding a new PII type (SSNs, credit cards, IP addresses, ...) is one new
entry in this list plus a `_find_x` function — not a new `if` branch
inside `scan()`. This mirrors the same registry pattern used at the
detector level (`app/registry.py`), just one layer down.

### 3.5 Overlap merging (`_merge_overlaps`)

All findings are detected first, against the **original, untouched**
text. Overlapping spans are then merged into their union — not "pick one
and discard the other" — specifically so a partial overlap between two
detector types can never leave part of either finding un-redacted. When
spans merge, the **higher-confidence** detector's `type` label wins, but
the redacted span always covers the full combined range.

### 3.6 Single-pass redaction (`_redact`)

Redaction happens in **one pass over the original text**, using
pre-computed, already-merged spans. This is explicitly what avoids a
subtle correctness bug: sequential `regex.sub()` calls (redact email, then
redact phone) can have an earlier replacement shift character offsets or
accidentally create a new false match for a later pattern to trip over.
Working from spans computed once against the untouched original text
sidesteps that class of bug entirely.

### 3.7 Per-type weighted scoring with diminishing returns

```
score = min( Σ over types: base_weight[type] + min(count-1, 4) * (base_weight[type] // 2),  40 )
```

- Base weight per type: **email = 10, phone = 15**.
- Each *additional* match of the same type (beyond the first) adds half
  that type's base weight, up to a cap of 4 extra matches counted —
  diminishing returns rather than linear scaling, so e.g. a document
  containing 50 email addresses doesn't score proportionally to 50x a
  single email.
- Total capped at **`_MAX_SCORE = 40`**.

This is a materially different design from the original flat "PII = 20
points, period" approach — see [§9.1](#91-scores-moved-from-policyyaml-into-the-detectors-themselves)
and [§11](#11-deviations-from-the-original-spec--flagged-explicitly) for
what that means for `policy.yaml`'s declared score.

### 3.8 Structured, redaction-safe evidence

```
"type=email count=2 spans=[(14, 33), (58, 71)]"
```

Evidence is grouped by type, includes match count and character spans,
and **never contains the matched value itself** — consistent with the
project-wide rule that a detector's own output can never leak the
sensitive data it just found.

### 3.9 Configurable redaction tokens

The constructor accepts an optional `tokens` dict merged over
`DEFAULT_TOKENS` (`{"email": "[REDACTED_EMAIL]", "phone":
"[REDACTED_PHONE]"}`), so a caller can override redaction tokens (e.g.
`"[EMAIL]"` instead) without touching detector internals. Unset by
default — existing behavior is unchanged for any caller not using this.

### 3.10 Constructor / backward compatibility

`PIIDetector(score: int = 20, tokens: Optional[Dict[str, str]] = None)` —
same story as prompt injection: `score` is kept for constructor
compatibility and used only as a fallback safety net
(`score = _score(findings) or self.score`), not as the primary scoring
path.

---

## 4. Detector: RAG Injection

`app/detectors/rag_injection.py` — the most architecturally interesting
piece, because of an explicit, documented decision to **share code with**
`prompt_injection.py` rather than duplicate it.

### 4.1 The core design decision: shared rule tables, not a second rule set

The code's own header comment explains this directly: this detector used
to carry an independently-maintained list of 4 signature patterns, while
`PromptInjectionDetector` carried the full category system covering the
same intent categories plus embedded instructions, multilingual keywords,
entropy, URLs, sequencing, and role-spoofing. That split meant **every
improvement to one detector silently didn't apply to the other** — and RAG
documents are arguably the *more* dangerous surface for indirect
injection (OWASP's classic case), so they deserve at least equal coverage.

The fix: `rag_injection.py` **imports the building blocks directly** from
`prompt_injection.py` — the `CATEGORIES` table, `_MULTILINGUAL_KEYWORDS`,
`_EMBEDDED_BLOCK_PATTERNS`, `_STRUCTURAL_PATTERNS`, encoded-payload
regexes/entropy function, URL regexes, the imperative-verb regex, and the
document-level signal functions (`_sequence_chain_hit`,
`_role_transition_hit`, `_contradiction_hit`,
`_context_window_stuffing_hit`, `_evasion_counts`). What stays local to
this file is exactly the **RAG-specific** part: offset-preserving
normalization and single-pass span redaction over the *original* document
text (prompt injection doesn't need this — it doesn't redact the prompt),
plus a few RAG-flavored signatures with no natural prompt-side equivalent.

**Tradeoff, stated plainly:** this makes the two detectors **no longer
fully independent** at the code level — `rag_injection.py` now has a hard
import dependency on `prompt_injection.py`. That's a deliberate departure
from the original "detectors don't know about each other" principle, made
in exchange for not maintaining two drifting copies of the same rule
table. Worth a second look if a future refactor wants detectors to be
independently deployable/pluggable modules.

### 4.2 Offset-preserving normalization

The hardest problem RAG injection has that prompt injection doesn't:
**detection happens on normalized text, but redaction must happen on the
original text**, at the original character offsets. A naive
"normalize, then match, then try to redact" pipeline breaks the moment
normalization changes string length (NFKC expansion, homoglyph
substitution, stripped zero-width characters, collapsed spaced-letter
evasion).

The fix is a **parallel index map** carried through every normalization
step:
- Strip Unicode format characters (general category `Cf`, plus soft
  hyphen) — while recording, per remaining character, its index in the
  original string.
- NFKC-normalize with map (a single input character can expand to
  multiple output characters — each output character keeps the *same*
  original-index it inherited from its source).
- Homoglyph-fold with map.
- Lowercase with map.
- Collapse spaced-letter evasion with map (collapsing "i g n o r e" into
  "ignore" removes the space characters — the map is updated to drop
  those positions too).
- Collapse space/tab runs with map (**deliberately preserves newlines** —
  unlike the prompt-injection version — because several structural
  patterns are `MULTILINE`-anchored to line starts, e.g. `SYSTEM:` at the
  beginning of a line; collapsing newlines away would break those
  anchors).

Any match found against the normalized view is translated back to
original-text coordinates via `_map_span_to_original()` immediately —
everything downstream (dampening, merging, redaction, scoring) works in
**one coordinate space** (original text) only.

### 4.3 Signature catalog

**RAG-specific signatures** (no clean prompt-side equivalent):

| Signature | Severity | Pattern intent |
|---|---|---|
| `system_directive` | 30 | `SYSTEM:` at the start of a line |
| `policy_override` | 25 | "override/bypass the policy/rules/guidelines/restrictions/filters" |
| `assistant_directive` | 15 | "assistant/you must (now/always) ignore/comply/obey" |

**Reused from prompt_injection.py** (regex-only — the fuzzy/paraphrase
matching layer from §2.3 is **not** applied here, a deliberate scope
tradeoff since it's tuned for conversational phrasing, not document text):
- All 8 category patterns (§2.2), at their original weights.
- All structural/fake-delimiter patterns (§2.6), at weight 20.

**Also detected independently in this file, same logic as prompt_injection.py:**
- Embedded/indirect instructions (§2.5) — arguably the single most
  relevant feature here, since this *is* OWASP's canonical indirect-
  injection case: an attacker poisoning a document that later gets
  retrieved into a RAG pipeline.
- Multilingual keyword hits (§2.4).
- URL/external-instruction-source signals (§2.8).
- Encoded payload detection — regex hits plus entropy (§2.7).

**Document-level signals** (no single redactable span — same functions as
prompt_injection.py, applied to the whole document): multi-stage
sequencing, role-transition spoofing, semantic contradiction,
context-window stuffing, and obfuscation/evasion density (§2.9–§2.11),
at their original weights.

### 4.4 Documentation-context dampening

RAG-specific false-positive guard, analogous to §2.13 but shaped for
document content rather than conversational prompts: a context document
that is *documentation about prompt injection* ("to detect attacks,
search for the phrase 'ignore previous instructions'") trips the same
signatures as an actual embedded attack.

Dampening applies (factor **0.3**, matches still redacted, just scored
lower) when a match falls:
- Inside a fenced code block (` ``` ... ``` `) or inline code (`` `...` ``).
- Within 80 characters *after* example-framing language ("for example",
  "e.g.", "such as", "sample phrase", "search for", "for instance").

### 4.5 Merge, redact, score

- **Merge** (`_merge_overlaps`): same union-of-overlapping-spans strategy
  as PII (§3.5), keeping the higher-severity signature's label but always
  covering the full combined span. Also propagates the `dampened` flag —
  if either overlapping finding was dampened, the merged finding is
  treated as dampened.
- **Redact** (`_redact`): single pass over the original text using merged,
  original-coordinate spans → `[REDACTED_INSTRUCTION]`.
- **Score** (`_score_findings` + document-level signals): for span
  findings, takes the *max* severity contribution per distinct signature
  ID (applying the 0.3 dampening factor where flagged) and sums across
  signature types; adds document-level signal weights on top; caps the
  total at `_MAX_SCORE = 100`.

### 4.6 Evidence format

```
"signature=system_directive severity=30 span=(120,145) dampened=False"
"signal=multi_stage_execution_chain weight=30 note=chained_imperatives"
```

Span findings and document-level signals get distinct evidence line
formats, both structured and free of any raw matched document text.

### 4.7 Constructor / backward compatibility

`RagInjectionDetector(score: int = 60)` — same pattern as the other two:
kept for constructor compatibility, used only as an unreachable-in-
practice fallback (`score = min(span_score + doc_score, _MAX_SCORE) or
self.score`).

---

## 5. Analyzer — orchestration details

`app/analyzer.py` remains thin, as designed — it contains **zero regex and
zero scoring math** of its own. What it actually does:

- **Prompt-side detectors** (`registry.detectors`) each scan
  `request.prompt` once.
- **Doc-side detectors** (`registry.doc_detectors`) scan *every*
  `context_docs[i].text`, producing `(doc_id, DetectorResult)` pairs —
  kept paired so sanitization can be mapped back to the correct document.
- **Score & decision**: delegates entirely to `combine_score()` /
  `decide()` from `policy_engine.py` (§8) — the analyzer never touches a
  threshold or a weight directly.
- **`risk_tags`**: returned as a **sorted set**, not insertion order —
  deliberately deterministic regardless of which order detectors happened
  to be registered in, mirroring the determinism guarantee the policy
  engine is expected to provide.
- **`reasons`**: one entry per *matched* detector, joining that detector's
  evidence list with `"; "` — falls back to a generic `"{tag} matched"`
  string if a detector matched but produced no evidence entries (a
  defensive fallback, not expected to trigger given current detectors).
- **`sanitized_prompt`**: iterates prompt-side results **in registry
  order**, and for any result that set `sanitized_text`, overwrites the
  running `text` variable. This means if more than one detector redacts
  the prompt in the future, later detectors' redactions apply *on top of*
  earlier ones rather than silently clobbering them — currently only PII
  sets `sanitized_text` on the prompt path, so this is forward-looking
  infrastructure more than an active behavior today.
- **`sanitized_context_docs`**: builds a `doc_id -> sanitized_text` map
  from doc-side results, then reconstructs the full `context_docs` list,
  falling back to each doc's original text if no detector redacted it.

---

## 6. API layer

`app/main.py` — unchanged in shape from the original plan, confirmed from
source:

- Exactly the 2 specified endpoints (`POST /analyze`, `GET /policy`), plus
  a **commented-out** `/health` route (not currently active) that would
  return `{"status": "ok", "policy_version": policy.version}` — a cheap
  liveness+config-loaded check, left in as a documented option rather than
  deleted.
- **Dependency injection via `Depends()`**, not module-level globals — the
  file's own docstring states this explicitly: it exists specifically so
  tests can use `app.dependency_overrides` to swap in a fake registry
  (e.g. one with `block_score=1`) to force the `BLOCK` path deterministically,
  without needing to craft an elaborate real prompt.
- **Zero scoring/threshold/detector logic in the route bodies** — each
  route is parse → delegate → return, exactly as designed.
- Response validation is via Pydantic `response_model=` on both routes,
  so a malformed internal response would itself raise rather than silently
  serialize incorrectly.

---

## 7. Streamlit UI

`streamlit_app.py` — confirmed as a pure HTTP client, no detector or
scoring logic, consistent with its own docstring and the CLI's design.
Features actually implemented:

- **Custom dark theme** (Inter + JetBrains Mono fonts, gradient background,
  card-based layout) — purely cosmetic, no functional impact.
- **Sidebar**: editable API base URL (defaults from `SENTRAGUARD_API_URL`
  env var), a "Check connection" button that calls `GET /policy` and
  displays a green/red status dot, and — when reachable — renders the
  **live policy config** (version, `block_score`, `transform_score`, and
  a per-detector weights table if `scores` is present in the response).
- **Input form**: prompt text area, a dynamic add/remove control for
  context documents, and metadata fields (`app_id`, `user_id`,
  `request_id` — the latter auto-generated from a timestamp by default).
- **Request handling**: distinguishes three outcomes explicitly —
  a `422` response (shows a "payload rejected" message), a
  `ConnectionError` (shows an "is it running?" hint with the exact uvicorn
  command to start it), and any other exception (generic error message).
- **Results panel**: color-coded decision banner (green/amber/red for
  allow/transform/block) with an icon, a Plotly gauge chart of
  `risk_score` with colored bands, risk tags as pills, a reasons list,
  the sanitized prompt in a monospace box, and — only when present —
  sanitized context docs per doc ID. Raw JSON response is available in a
  collapsible expander.

See [§11](#11-deviations-from-the-original-spec--flagged-explicitly) for
two implementation details worth double-checking against intent (context
doc limit, and hardcoded gauge thresholds).

---

## 8. Scoring & Policy Engine (inferred)

**Not directly confirmed from source** — `policy_engine.py` wasn't
available for this pass. From how `analyzer.py` calls it
(`combine_score(all_results)`, `decide(score, registry.thresholds)`), we
can infer:

- `combine_score` takes the full flat list of `DetectorResult`s (prompt-
  side and doc-side combined) and returns a single 0–100 integer.
- `decide` takes that score plus a `thresholds` object (presumably
  `block_score` / `transform_score`, sourced from `policy.yaml` via
  `registry.thresholds`) and returns one of `allow`/`transform`/`block`.

What's **not** confirmed: whether `combine_score` still does the simple
"sum, capped at 100" from the original MVP design, given that individual
detector scores are now themselves the output of much more sophisticated
internal weighting (§9.1). This is worth verifying directly against
`policy_engine.py`'s actual source before treating the score-range table
in the README as precise.

---

## 9. Cross-cutting design decisions

### 9.1 Scores moved from `policy.yaml` into the detectors themselves

The original design (and the README's score table) describes each
detector as contributing a **flat, fixed** score sourced from
`policy.yaml`: `prompt_injection: 70`, `pii: 20`, `rag_injection: 60`. All
three detector constructors still *accept* a `score` parameter for
exactly this reason — call-site compatibility with that design.

**In the current implementation, none of them primarily use it.** Each
detector now computes its own score dynamically:
- Prompt injection: sum of fired category/signal weights (§2.14), 0–100.
- PII: per-type weighted count with diminishing returns (§3.7), 0–40.
- RAG injection: sum of per-signature max severities + document-level
  signals (§4.5), 0–100.

The constructor `score` parameter is now used only as a **fallback safety
net** (`... or self.score`) for the edge case where a detector reports
`matched=True` but its computed score comes out to `0` — not the normal
scoring path.

**Why this matters for production discussion:** `GET /policy` still
returns the flat scores from `policy.yaml` as if they were authoritative
— a caller reading that endpoint would reasonably assume "prompt
injection always contributes exactly 70 points," which is no longer true.
If `policy.yaml`'s `scores` section is being used anywhere as documentation
of actual system behavior (dashboards, compliance docs, tuning
discussions), it should either be updated to reflect that scores are now
dynamic ranges, or `/policy` should be extended to expose the real
weight tables per detector.

### 9.2 Redaction correctness: detect-then-merge-then-redact, always

Both PII and RAG injection independently arrived at the same three-phase
pattern: **detect everything against the original text first → merge
overlapping spans → redact in one pass at the end.** This is called out
explicitly in both files' comments as the fix for a specific class of bug
(sequential `regex.sub()` calls shifting offsets and creating accidental
new matches for later patterns). Any future PII/injection detector should
follow this same pattern rather than reintroducing per-pattern sequential
substitution.

### 9.3 Evidence is structured and redaction-safe everywhere

Every detector's evidence strings follow the same rule established at the
project's start: generic, structured (`type=X count=N`, `signature=Y
severity=Z span=(a,b)`), and never contain the raw matched value. This
held consistently through the evolution from flat regex detectors to the
current weighted-signal engines — worth calling out as a constraint that
successfully survived a significant rewrite, not just an initial-commit
intention.

### 9.4 Shared code between prompt_injection.py and rag_injection.py

Covered in depth in §4.1 — noted again here because it's a project-wide
tradeoff, not just a RAG-injection implementation detail: the "detectors
are fully independent, know nothing about each other" principle from the
original plan has been deliberately relaxed in one place, in exchange for
a single source of truth on attack categories. Any future change to
`CATEGORIES`, `_MULTILINGUAL_KEYWORDS`, or the embedded-instruction/
structural pattern tables in `prompt_injection.py` automatically propagates
to `rag_injection.py` — which is the intended benefit, but also means
`rag_injection.py` cannot be tested, deployed, or reasoned about in
complete isolation from `prompt_injection.py` anymore.

---

## 10. Known limitations & production hardening roadmap

Consolidated from in-code comments across all three detectors, plus
project-level gaps:

**Detection approach:**
- All detection is **regex/heuristic-based, not ML/semantic**. This is a
  deliberate MVP choice (deterministic, offline, no model dependency,
  fully unit-testable) — but it means every signal here is a proxy for
  intent, not an understanding of it.
- **Homoglyph coverage is intentionally partial** — covers observed
  jailbreak lookalikes, not the full Unicode confusables table. A
  motivated attacker with access to the source could find an uncovered
  character.
- **Multilingual coverage is a keyword list for 8 languages**, not
  translation — a language outside that list, or a paraphrase within a
  covered language that doesn't match the literal keywords, will not be
  caught by that layer (though other layers — entropy, structural,
  statistical — may still catch it).
- **The educational/meta-discussion dampener (§2.13, §4.4) is shallow
  pattern recognition, not intent modeling** — it can both under- and
  over-dampen: a well-disguised attack phrased as "for example, how would
  someone bypass safety filters..." could be dampened when it shouldn't
  be, while a genuinely academic discussion using unusual phrasing might
  not be recognized as such.
- **Fuzzy/paraphrase matching (§2.3) is not applied to RAG documents** —
  only literal regex signatures. A paraphrased injection embedded in a
  retrieved document has a narrower detection surface than the same
  paraphrase typed directly as a prompt.

**Scoring & policy:**
- `policy.yaml`'s declared per-detector scores are now stale relative to
  actual detector behavior (§9.1) — needs either a documentation update or
  an API change to stay accurate.
- Whether `combine_score`'s cross-detector combination strategy (sum vs.
  max vs. something else) still makes sense given that individual
  detector scores now range 0–100 (prompt injection, RAG injection) or
  0–40 (PII) rather than flat constants is worth re-examining directly
  against `policy_engine.py`'s source.
- Policy is loaded once at process startup from `policy.yaml` — no
  hot-reload; a threshold change requires a restart.

**Operational:**
- **No authentication or rate limiting** on either API endpoint — would
  sit at an API gateway/middleware layer in production, not in this
  service.
- **No structured logging/observability layer** — evidence is
  redaction-safe by design, but there's currently no logging pipeline
  documented that captures decisions for audit/monitoring at scale.
- **Stateless service** — horizontally scalable behind a load balancer
  with no code changes required, which is the one operational property
  that comes for free from the current design.

---

## 11. Deviations from the original spec — flagged explicitly

Two implementation details in `streamlit_app.py` don't match the written
spec exactly. Neither is necessarily wrong, but both are worth a
deliberate "yes, keep it this way" decision rather than an accidental
drift:

1. **Context document limit.** The spec calls for "0–3 context documents."
   The implemented `st.session_state.num_docs` add/remove control allows
   up to **6** (`disabled=st.session_state.num_docs >= 6`). If 3 was a
   hard UX/API constraint, this should be tightened; if 3 was just an
   example count, 6 is a reasonable and harmless relaxation.

2. **Gauge chart thresholds are hardcoded, not fetched.** The Plotly risk
   gauge draws its green/amber/red bands at fixed `0–40 / 40–80 / 80–100`
   ranges, regardless of what `GET /policy` actually reports for
   `transform_score`/`block_score`. The sidebar *does* fetch and display
   the real thresholds as numbers, but the visual gauge itself doesn't
   consume them — so if `policy.yaml` is ever tuned to different
   thresholds, the gauge's colored bands will visually mislead relative to
   the actual decision boundaries. Worth wiring the gauge's `steps` to the
   fetched policy values rather than the current constants.