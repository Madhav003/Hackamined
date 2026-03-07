"""
=============================================================================
PII Shield — Configuration Module
=============================================================================
Central configuration for encryption keys, Presidio settings, and logging.

SECURITY NOTE (for hackathon judges):
    In production, AES keys MUST come from a Hardware Security Module (HSM)
    or a cloud KMS (AWS KMS / Azure Key Vault / GCP Cloud KMS).
    Keys shown here are generated at runtime for demonstration only.
=============================================================================
"""

import os
import logging

# ---------------------------------------------------------------------------
# Encryption Configuration
# ---------------------------------------------------------------------------

# AES-256 requires a 32-byte key. Generated fresh each run for demo purposes.
# PRODUCTION: Retrieve from a KMS; never hard-code or commit keys.
AES_KEY: bytes = os.urandom(32)

# Format-Preserving Encryption (FF3-1) configuration.
# FF3 requires a 16-byte key and a 7-byte tweak (FF3-1 spec).
FPE_KEY: bytes = os.urandom(16)
FPE_TWEAK: bytes = os.urandom(7)

# ---------------------------------------------------------------------------
# Presidio Entity Configuration
# ---------------------------------------------------------------------------

# Supported entity types (built-in + custom Indian entities)
ENTITY_TYPES = [
    # Built-in Presidio entities
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "US_SSN",
    "LOCATION",
    "DATE_TIME",
    "URL",
    # Custom Indian PII entities
    "IN_AADHAAR",
    "IN_PAN",
    # Biometric / hashed data
    "BIOMETRIC_HASH",
]

# Minimum confidence threshold for Presidio detections
MIN_CONFIDENCE_SCORE: float = 0.4

# ---------------------------------------------------------------------------
# Threat Level Scoring Weights
# ---------------------------------------------------------------------------
# Higher weight = more sensitive PII type.
# These weights reflect financial/regulatory risk (PCI-DSS, GDPR, India DPDP).

ENTITY_RISK_WEIGHTS: dict[str, int] = {
    "IN_AADHAAR":     10,   # India's national biometric ID — extremely sensitive
    "US_SSN":         10,   # Social Security Number
    "CREDIT_CARD":     9,   # PCI-DSS regulated
    "IN_PAN":          8,   # Tax identifier — identity theft risk
    "PHONE_NUMBER":    5,   # Can enable SIM-swap attacks
    "EMAIL_ADDRESS":   4,   # Phishing vector
    "IP_ADDRESS":      3,   # Network reconnaissance
    "LOCATION":        3,   # Physical security risk
    "DATE_TIME":       2,   # Low risk alone, high when combined
    "PERSON":          2,   # Name alone is low risk
    "URL":             1,   # Minimal direct risk
    "BIOMETRIC_HASH":  10,  # Biometric identifiers — extremely sensitive
}

# Threat level thresholds (cumulative weighted score)
THREAT_THRESHOLDS = {
    "LOW":      10,    # Score < 10
    "MEDIUM":   30,    # 10 <= Score < 30
    "HIGH":     60,    # 30 <= Score < 60
    # Score >= 60 → CRITICAL
}

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_LEVEL = logging.INFO

# Audit log persistence file (JSON lines)
AUDIT_LOG_FILE = "audit_log.json"

# ---------------------------------------------------------------------------
# Database Configuration (SQLite for demo, PostgreSQL in production)
# ---------------------------------------------------------------------------

DATABASE_PATH = "pii_shield.db"

# ---------------------------------------------------------------------------
# OCR Configuration
# ---------------------------------------------------------------------------

# Path to Tesseract executable (adjust for your OS)
# Windows default: r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# Linux/macOS: usually on PATH already
TESSERACT_CMD: str | None = None  # None = use system PATH

logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
