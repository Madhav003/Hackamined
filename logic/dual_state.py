"""
=============================================================================
PII Shield — Dual-State Processing Module
=============================================================================
Generates two parallel views of PII data:

1. MASKED VIEW (for standard users / analysts):
   - Human-readable redaction: [REDACTED], partial masks (j***@email.com)
   - Safe for display, reporting, and non-privileged access

2. ENCRYPTED RAW (for secure storage / admin recovery):
   - AES-256-GCM for general PII (names, emails, addresses)
   - Format-Preserving Encryption for numeric PII (credit cards, phones)
   - Only decryptable by authorized admins with the key

This dual-state approach satisfies:
  • GDPR Article 32: Encryption of personal data
  • PCI-DSS Requirement 3: Protect stored cardholder data
  • India DPDP Act: Reasonable security safeguards
=============================================================================
"""

import logging
from dataclasses import dataclass, field
from typing import List

from presidio_analyzer import RecognizerResult

from encryption import AESCipher, FPECipher

logger = logging.getLogger(__name__)

# Entity types that should use FPE (numeric, fixed-length)
FPE_ELIGIBLE_ENTITIES = {"CREDIT_CARD", "PHONE_NUMBER", "IN_AADHAAR"}


@dataclass
class PIIEntity:
    """Represents a single detected PII entity with both views."""
    entity_type: str
    original_text: str
    masked_text: str
    encrypted_data: dict | str  # dict for AES, str for FPE
    encryption_method: str      # "AES-256-GCM" or "FF3-1-FPE"
    confidence: float
    start: int
    end: int


@dataclass
class DualStateRecord:
    """
    Complete dual-state record for a processed document.
    
    Contains the masked view (safe for display) and a list of
    encrypted PII entities (safe for storage, recoverable by admin).
    """
    original_length: int
    masked_text: str
    entities: List[PIIEntity] = field(default_factory=list)
    entity_count: int = 0

    def __post_init__(self):
        self.entity_count = len(self.entities)


def _mask_entity(text: str, entity_type: str) -> str:
    """
    Generate a human-readable masked version of a PII value.
    
    Masking strategies vary by entity type to maintain readability
    while ensuring PII is not exposed.
    """
    if entity_type == "EMAIL_ADDRESS" and "@" in text:
        # j***@email.com — show first char, mask middle, show domain
        local, domain = text.split("@", 1)
        if len(local) > 1:
            masked_local = local[0] + "*" * (len(local) - 1)
        else:
            masked_local = "*"
        return f"{masked_local}@{domain}"

    elif entity_type == "PHONE_NUMBER":
        # Show last 4 digits: XXXXXX7890
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) >= 4:
            return "X" * (len(digits) - 4) + digits[-4:]
        return "X" * len(text)

    elif entity_type == "CREDIT_CARD":
        # Show last 4 digits: XXXX-XXXX-XXXX-1234
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) >= 4:
            masked = "X" * (len(digits) - 4) + digits[-4:]
            # Restore dashes/spaces if present
            if "-" in text:
                return "-".join([masked[i:i+4] for i in range(0, len(masked), 4)])
            return masked
        return "X" * len(text)

    elif entity_type == "IN_AADHAAR":
        # Show last 4 digits: XXXX XXXX 1234
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) >= 4:
            masked = "X" * (len(digits) - 4) + digits[-4:]
            if " " in text:
                return f"{masked[:4]} {masked[4:8]} {masked[8:]}"
            return masked
        return "X" * len(text)

    elif entity_type == "IN_PAN":
        # Show first 2 and last 1: AB********E
        if len(text) >= 3:
            return text[:2] + "*" * (len(text) - 3) + text[-1]
        return "[REDACTED_PAN]"

    elif entity_type == "PERSON":
        return "[REDACTED_NAME]"

    elif entity_type == "US_SSN":
        return "[REDACTED_SSN]"

    else:
        return "[REDACTED]"


def _encrypt_entity(
    text: str,
    entity_type: str,
    aes_cipher: AESCipher,
    fpe_cipher: FPECipher,
) -> tuple:
    """
    Encrypt a PII value using the appropriate method.
    
    Returns (encrypted_data, method_name):
      - FPE for numeric entities → dict-free string of same length
      - AES-GCM for everything else → dict with ciphertext/nonce/tag
    """
    if entity_type in FPE_ELIGIBLE_ENTITIES:
        # Extract digits only for FPE
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) >= 6:  # FF3-1 minimum
            try:
                encrypted = fpe_cipher.encrypt_numeric(digits)
                return encrypted, "FF3-1-FPE"
            except Exception as e:
                logger.warning("FPE failed for %s, falling back to AES: %s", entity_type, e)

    # Default: AES-256-GCM
    encrypted = aes_cipher.encrypt(text)
    return encrypted, "AES-256-GCM"


def generate_dual_state(
    text: str,
    results: List[RecognizerResult],
    aes_cipher: AESCipher | None = None,
    fpe_cipher: FPECipher | None = None,
) -> DualStateRecord:
    """
    Process analyzed text into a dual-state record.
    
    Args:
        text: Original text that was analyzed
        results: Presidio RecognizerResult list from analysis
        aes_cipher: AES-256 cipher instance (created if None)
        fpe_cipher: FPE cipher instance (created if None)
        
    Returns:
        DualStateRecord with masked view + encrypted entities
    """
    if aes_cipher is None:
        aes_cipher = AESCipher()
    if fpe_cipher is None:
        fpe_cipher = FPECipher()

    # Sort results by start position (descending) for safe text replacement
    sorted_results = sorted(results, key=lambda r: r.start, reverse=True)

    entities = []
    masked_text = text

    for result in sorted_results:
        original = text[result.start:result.end]
        masked = _mask_entity(original, result.entity_type)
        encrypted_data, method = _encrypt_entity(
            original, result.entity_type, aes_cipher, fpe_cipher
        )

        entity = PIIEntity(
            entity_type=result.entity_type,
            original_text=original,
            masked_text=masked,
            encrypted_data=encrypted_data,
            encryption_method=method,
            confidence=result.score,
            start=result.start,
            end=result.end,
        )
        entities.append(entity)

        # Apply mask to the text
        masked_text = masked_text[:result.start] + masked + masked_text[result.end:]

    # Reverse to maintain original order
    entities.reverse()

    record = DualStateRecord(
        original_length=len(text),
        masked_text=masked_text,
        entities=entities,
    )

    logger.info("Dual-state processing complete: %d entities (AES: %d, FPE: %d)",
                len(entities),
                sum(1 for e in entities if e.encryption_method == "AES-256-GCM"),
                sum(1 for e in entities if e.encryption_method == "FF3-1-FPE"))

    return record
