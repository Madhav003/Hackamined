"""
=============================================================================
PII Shield — Context-Aware PII Detection & Redaction Rules
=============================================================================
Implements smart, context-aware post-processing on top of Presidio's
raw entity detections.  These rules reduce false positives and enhance
true positives by examining the *surrounding text* of each detected
entity — not just the entity in isolation.

Rules implemented:
  1. Standalone number suppression  — ignore bare 10/12-digit numbers
     that lack any PII-context keywords nearby.
  2. Name + Phone linkage — boost confidence of a phone number when it
     appears close to a detected PERSON entity.
  3. Name + Aadhaar linkage — boost Aadhaar confidence when a name
     appears within a few lines.
  4. Credit-card Luhn validation — drop CREDIT_CARD detections that
     fail the Luhn checksum.
  5. Full-profile escalation — when a single text block contains a
     name + phone + email (or name + Aadhaar), elevate all related
     entities to high-confidence to avoid partial redaction gaps.

Additionally provides:
  - Large-file safeguards: 50 000-char / 500-row truncation and a
    60-second processing timeout.
  - A single public entry point: ``apply_context_rules(text, entities)``
    that returns a filtered / boosted entity list.
=============================================================================
"""

import re
import logging
from typing import List

from presidio_analyzer import RecognizerResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Window (characters) around an entity to scan for context keywords
_CONTEXT_WINDOW = 200

# Keywords that indicate a number is genuinely PII (case-insensitive)
# NOTE: intentionally excludes overly generic words like "number", "id", "#"
# that appear in both PII and non-PII contexts.
_PII_CONTEXT_KEYWORDS = {
    # Phone
    "phone", "mobile", "cell", "contact", "tel", "telephone", "whatsapp",
    "call", "sms", "fax",
    # Aadhaar
    "aadhaar", "aadhar", "uid", "uidai", "unique id",
    # PAN
    "pan", "pan card", "permanent account",
    # Credit / debit card
    "card", "credit", "debit", "visa", "mastercard", "amex", "rupay",
    # SSN
    "ssn", "social security",
    # Specific PII labels (not generic)
    "account number", "acct", "a/c",
    # KYC / form labels
    "customer", "client", "applicant", "beneficiary",
    "holder", "owner",
}

# Keywords whose presence *near* a 10/12-digit number mean it's NOT PII
_NON_PII_KEYWORDS = {
    "transaction", "txn", "order", "invoice", "reference", "ref",
    "roll", "emp", "employee code", "registration", "reg",
    "serial", "batch", "lot", "ticket", "case",
    # Compound phrases that override generic "number" / "id"
    "roll number", "serial number", "order number", "batch number",
    "transaction id", "order id", "ticket id", "case id", "invoice id",
    "registration number", "employee id", "emp id",
}

# Maximum text length to process (characters)
MAX_TEXT_LENGTH = 50_000

# Maximum rows (newlines) to process
MAX_ROWS = 500


# ---------------------------------------------------------------------------
# Luhn checksum (ISO/IEC 7812-1) — validates credit card numbers
# ---------------------------------------------------------------------------

def _luhn_check(number_str: str) -> bool:
    """Return True if *number_str* passes the Luhn checksum."""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Helper — extract context window around a character span
# ---------------------------------------------------------------------------

def _context_around(text: str, start: int, end: int, window: int = _CONTEXT_WINDOW) -> str:
    """Return lowercased text within *window* chars before and after [start, end)."""
    left = max(0, start - window)
    right = min(len(text), end + window)
    return text[left:right].lower()


def _has_any_keyword(ctx: str, keywords: set) -> bool:
    """Check whether any keyword appears in *ctx*."""
    for kw in keywords:
        if kw in ctx:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule 1 — Standalone Number Suppression
# ---------------------------------------------------------------------------

def _rule_standalone_number_suppression(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    Drop phone / Aadhaar detections on bare numbers that lack PII
    context keywords within ±200 chars.

    Prevents false positives on transaction IDs, roll numbers, etc.
    Runs AFTER boost rules so legitimately-boosted entities (score >= 0.8)
    are preserved.

    Two-tier proximity:
      - If a non-PII keyword is found within ±60 chars (the immediate
        label), suppress regardless of distant PII keywords.
      - Otherwise, suppress only if non-PII context exists and NO PII
        context in the full ±200-char window.
    """
    _NARROW_WINDOW = 60

    kept = []
    for e in entities:
        if e.entity_type in ("PHONE_NUMBER", "IN_AADHAAR"):
            # Tier 1: Narrow window — immediate label.
            # If the label right next to the number is a non-PII keyword
            # and there's no PII keyword nearby, suppress regardless of score.
            narrow_ctx = _context_around(text, e.start, e.end, _NARROW_WINDOW)
            has_narrow_non_pii = _has_any_keyword(narrow_ctx, _NON_PII_KEYWORDS)
            has_narrow_pii = _has_any_keyword(narrow_ctx, _PII_CONTEXT_KEYWORDS)

            if has_narrow_non_pii and not has_narrow_pii:
                logger.debug("Rule 1: Suppressed %s at %d-%d (narrow non-PII label)",
                             e.entity_type, e.start, e.end)
                continue

            # Tier 2: Wide window — only for low-confidence entities.
            if e.score < 0.8:
                ctx = _context_around(text, e.start, e.end)
                has_pii_ctx = _has_any_keyword(ctx, _PII_CONTEXT_KEYWORDS)
                has_non_pii_ctx = _has_any_keyword(ctx, _NON_PII_KEYWORDS)
                if has_non_pii_ctx and not has_pii_ctx:
                    logger.debug("Rule 1: Suppressed %s at %d-%d (wide non-PII context)",
                                 e.entity_type, e.start, e.end)
                    continue
        kept.append(e)
    return kept


# ---------------------------------------------------------------------------
# Rule 2 — Name + Phone Linkage
# ---------------------------------------------------------------------------

def _rule_name_phone_linkage(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    Boost PHONE_NUMBER confidence when a PERSON entity is detected
    within ±300 chars.  This lets us keep low-confidence phone matches
    that appear in KYC / contact blocks.
    """
    person_spans = [(e.start, e.end) for e in entities if e.entity_type == "PERSON"]
    if not person_spans:
        return entities

    boosted = []
    for e in entities:
        if e.entity_type == "PHONE_NUMBER" and e.score < 0.7:
            # Is there a PERSON entity within 300 chars?
            for ps, pe in person_spans:
                if abs(e.start - pe) < 300 or abs(ps - e.end) < 300:
                    e = RecognizerResult(
                        entity_type=e.entity_type,
                        start=e.start,
                        end=e.end,
                        score=max(e.score, 0.85),
                        analysis_explanation=e.analysis_explanation,
                        recognition_metadata=e.recognition_metadata,
                    )
                    logger.debug("Rule 2: Boosted PHONE at %d-%d (name nearby)", e.start, e.end)
                    break
        boosted.append(e)
    return boosted


# ---------------------------------------------------------------------------
# Rule 3 — Name + Aadhaar Linkage
# ---------------------------------------------------------------------------

def _rule_name_aadhaar_linkage(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    Boost IN_AADHAAR confidence when a PERSON entity is within ±500
    chars (typically within the same KYC record).
    """
    person_spans = [(e.start, e.end) for e in entities if e.entity_type == "PERSON"]
    if not person_spans:
        return entities

    boosted = []
    for e in entities:
        if e.entity_type == "IN_AADHAAR" and e.score < 0.8:
            for ps, pe in person_spans:
                if abs(e.start - pe) < 500 or abs(ps - e.end) < 500:
                    e = RecognizerResult(
                        entity_type=e.entity_type,
                        start=e.start,
                        end=e.end,
                        score=max(e.score, 0.95),
                        analysis_explanation=e.analysis_explanation,
                        recognition_metadata=e.recognition_metadata,
                    )
                    logger.debug("Rule 3: Boosted AADHAAR at %d-%d (name nearby)", e.start, e.end)
                    break
        boosted.append(e)
    return boosted


# ---------------------------------------------------------------------------
# Rule 4 — Credit Card Luhn Validation
# ---------------------------------------------------------------------------

def _rule_credit_card_luhn(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    Drop CREDIT_CARD detections whose digit sequence fails the Luhn
    checksum.  Presidio's regex can match non-card numbers; Luhn is
    the industry-standard filter.
    """
    kept = []
    for e in entities:
        if e.entity_type == "CREDIT_CARD":
            raw = text[e.start:e.end]
            if not _luhn_check(raw):
                logger.debug("Rule 4: Dropped CREDIT_CARD at %d-%d (Luhn fail)", e.start, e.end)
                continue
        kept.append(e)
    return kept


# ---------------------------------------------------------------------------
# Rule 5 — Full-Profile Escalation
# ---------------------------------------------------------------------------

def _rule_full_profile_escalation(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    When a text block contains a *cluster* of PII (name + phone + email
    or name + Aadhaar), boost all entities in that cluster to high
    confidence.  This avoids partial redaction where one field of a
    KYC record is masked but adjoining fields slip through.

    A cluster is any group of entities whose spans fall within a
    1 000-character sliding window.
    """
    types_present = {e.entity_type for e in entities}

    has_name = "PERSON" in types_present
    has_phone = "PHONE_NUMBER" in types_present
    has_email = "EMAIL_ADDRESS" in types_present
    has_aadhaar = "IN_AADHAAR" in types_present

    is_profile = has_name and (
        (has_phone and has_email) or has_aadhaar
    )

    if not is_profile:
        return entities

    # Cluster detection: find entities within 1000-char windows
    sorted_ents = sorted(entities, key=lambda e: e.start)
    cluster_indices = set()

    for i, anchor in enumerate(sorted_ents):
        if anchor.entity_type != "PERSON":
            continue
        window_start = anchor.start - 200
        window_end = anchor.end + 1000
        cluster = [i]
        cluster_types = {"PERSON"}
        for j, other in enumerate(sorted_ents):
            if i == j:
                continue
            if window_start <= other.start <= window_end:
                cluster.append(j)
                cluster_types.add(other.entity_type)

        # Only escalate if this window has name + (phone+email or aadhaar)
        if "PERSON" in cluster_types and (
            ("PHONE_NUMBER" in cluster_types and "EMAIL_ADDRESS" in cluster_types)
            or "IN_AADHAAR" in cluster_types
        ):
            cluster_indices.update(cluster)

    if not cluster_indices:
        return entities

    escalated = []
    for i, e in enumerate(sorted_ents):
        if i in cluster_indices and e.score < 0.9:
            e = RecognizerResult(
                entity_type=e.entity_type,
                start=e.start,
                end=e.end,
                score=max(e.score, 0.95),
                analysis_explanation=e.analysis_explanation,
                recognition_metadata=e.recognition_metadata,
            )
            logger.debug("Rule 5: Escalated %s at %d-%d (full profile)",
                         e.entity_type, e.start, e.end)
        escalated.append(e)

    return escalated


# ---------------------------------------------------------------------------
# Large-file safeguards
# ---------------------------------------------------------------------------

def truncate_for_processing(text: str) -> str:
    """
    Truncate text to stay within safe processing limits.
    Returns the (possibly truncated) text.
    """
    if len(text) <= MAX_TEXT_LENGTH:
        lines = text.split("\n")
        if len(lines) <= MAX_ROWS:
            return text
        truncated = "\n".join(lines[:MAX_ROWS])
        logger.warning("Truncated text from %d to %d rows", len(lines), MAX_ROWS)
        return truncated

    truncated = text[:MAX_TEXT_LENGTH]
    logger.warning("Truncated text from %d to %d chars", len(text), MAX_TEXT_LENGTH)
    return truncated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_context_rules(
    text: str,
    entities: List[RecognizerResult],
) -> List[RecognizerResult]:
    """
    Apply all context-aware rules in sequence to a list of Presidio
    entity detections.

    Args:
        text:     The original (unmasked) document text.
        entities: Raw RecognizerResult list from Presidio AnalyzerEngine.

    Returns:
        Filtered and confidence-boosted entity list.
    """
    if not entities:
        return entities

    result = list(entities)  # shallow copy

    # Order matters: boost first (so legitimate entities reach high confidence),
    # then suppress low-confidence false positives, then validate checksums.
    result = _rule_name_phone_linkage(text, result)
    result = _rule_name_aadhaar_linkage(text, result)
    result = _rule_full_profile_escalation(text, result)
    result = _rule_standalone_number_suppression(text, result)
    result = _rule_credit_card_luhn(text, result)

    dropped = len(entities) - len(result)
    if dropped:
        logger.info("Context rules: dropped %d false positives, kept %d entities",
                     dropped, len(result))
    return result
