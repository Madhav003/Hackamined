"""
=============================================================================
PII Shield — Presidio Analyzer & Anonymizer Engine Setup
=============================================================================
Configures the Presidio pipeline with custom Indian recognizers and
provides helper functions for text analysis and anonymization.
=============================================================================
"""

import logging
from typing import List

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from recognizers import IndianAadhaarRecognizer, IndianPanRecognizer, IndianNameRecognizer
from config import ENTITY_TYPES, MIN_CONFIDENCE_SCORE

logger = logging.getLogger(__name__)


def create_analyzer() -> AnalyzerEngine:
    """
    Build a Presidio AnalyzerEngine with:
      • All default built-in recognizers (PERSON, EMAIL, CREDIT_CARD, etc.)
      • Custom Indian Aadhaar recognizer (with Verhoeff validation)
      • Custom Indian PAN recognizer (with entity-type validation)
    """
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()  # Load built-in recognizers

    # Register custom Indian PII recognizers
    registry.add_recognizer(IndianAadhaarRecognizer())
    registry.add_recognizer(IndianPanRecognizer())
    registry.add_recognizer(IndianNameRecognizer())

    analyzer = AnalyzerEngine(registry=registry)
    logger.info("AnalyzerEngine initialized with %d recognizers", len(registry.recognizers))
    return analyzer


def create_anonymizer() -> AnonymizerEngine:
    """Create the Presidio AnonymizerEngine (stateless — just needs operators)."""
    return AnonymizerEngine()


# ---------------------------------------------------------------------------
# Default operator configuration for anonymization
# ---------------------------------------------------------------------------
# Maps each entity type to its masking strategy.

DEFAULT_OPERATORS = {
    "PERSON":        OperatorConfig("replace", {"new_value": "[REDACTED_NAME]"}),
    "EMAIL_ADDRESS": OperatorConfig("mask",    {"type": "mask", "masking_char": "*",
                                                "chars_to_mask": 6, "from_end": False}),
    "PHONE_NUMBER":  OperatorConfig("mask",    {"type": "mask", "masking_char": "X",
                                                "chars_to_mask": 6, "from_end": False}),
    "CREDIT_CARD":   OperatorConfig("mask",    {"type": "mask", "masking_char": "X",
                                                "chars_to_mask": 12, "from_end": False}),
    "IN_AADHAAR":    OperatorConfig("mask",    {"type": "mask", "masking_char": "X",
                                                "chars_to_mask": 8, "from_end": False}),
    "IN_PAN":        OperatorConfig("replace", {"new_value": "[REDACTED_PAN]"}),
    "US_SSN":        OperatorConfig("replace", {"new_value": "[REDACTED_SSN]"}),
    "IP_ADDRESS":    OperatorConfig("replace", {"new_value": "[REDACTED_IP]"}),
    "LOCATION":      OperatorConfig("replace", {"new_value": "[REDACTED_LOCATION]"}),
    "DATE_TIME":     OperatorConfig("replace", {"new_value": "[REDACTED_DATE]"}),
    "URL":           OperatorConfig("replace", {"new_value": "[REDACTED_URL]"}),
    "DEFAULT":       OperatorConfig("replace", {"new_value": "[REDACTED]"}),
}


def analyze_text(
    analyzer: AnalyzerEngine,
    text: str,
    language: str = "en",
    entities: List[str] | None = None,
    score_threshold: float = MIN_CONFIDENCE_SCORE,
) -> List[RecognizerResult]:
    """
    Run Presidio analysis on a text string.
    
    Returns a list of RecognizerResult objects, each containing:
      - entity_type: str
      - start: int (character offset)
      - end: int (character offset)
      - score: float (confidence 0.0-1.0)
    """
    if entities is None:
        entities = ENTITY_TYPES

    results = analyzer.analyze(
        text=text,
        language=language,
        entities=entities,
        score_threshold=score_threshold,
    )
    logger.info("Analysis found %d PII entities in text of length %d", len(results), len(text))
    return results


def anonymize_text(
    anonymizer: AnonymizerEngine,
    text: str,
    results: List[RecognizerResult],
    operators: dict | None = None,
) -> str:
    """
    Apply anonymization to text based on analysis results.
    Returns the anonymized text string.
    """
    if operators is None:
        operators = DEFAULT_OPERATORS

    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )
    return anonymized.text
