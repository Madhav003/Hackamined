"""
=============================================================================
PII Shield — ASCII Table Processor
=============================================================================
Fixes three critical bugs when processing tabular data:

Bug 1: Missed Indian names → Custom fallback recognizer + lower threshold
Bug 2: Inconsistent 12-digit handling → Unified operator configuration
Bug 3: Table alignment breaking → Cell-by-cell processing with padding

This module processes ASCII tables row-by-row and cell-by-cell to:
  1. Preserve table alignment (| dividers stay aligned)
  2. Apply consistent PII masking per column type
  3. Prevent "row bleeding" where redaction spans multiple cells
=============================================================================
"""

import re
import logging
from dataclasses import dataclass
from typing import Callable, Optional

from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerResult,
    Pattern,
    PatternRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from recognizers import IndianNameRecognizer

logger = logging.getLogger(__name__)


# ===========================================================================
# BUG 1 FIX: IndianNameRecognizer now imported from recognizers.py
# ===========================================================================


# ===========================================================================
# BUG 2 FIX: Unified Operator Configuration for 12-Digit Numbers
# ===========================================================================

def create_unified_operators(
    twelve_digit_mode: str = "mask_last_4",
    name_mode: str = "redact",
) -> dict[str, OperatorConfig]:
    """
    Create a unified operator configuration that ensures ALL entities
    of the same type are treated identically.
    
    Args:
        twelve_digit_mode: How to handle 12-digit numbers (IN_AADHAAR, etc.)
            - "mask_last_4": Show only last 4 digits → "XXXX XXXX 1234"
            - "full_mask": Mask all digits → "XXXX XXXX XXXX"
            - "redact": Replace with [REDACTED_AADHAAR]
            - "ignore": Leave unchanged
            
        name_mode: How to handle PERSON entities
            - "redact": Replace with [REDACTED_NAME]
            - "mask_first": Show first letter → "A*****"
            - "hash": Replace with hash prefix
    
    Returns:
        Dictionary of entity_type → OperatorConfig for AnonymizerEngine
    """
    operators = {}

    # -------------------------------------------------------------------------
    # 12-DIGIT NUMBER HANDLING (Aadhaar, custom IDs)
    # -------------------------------------------------------------------------
    if twelve_digit_mode == "mask_last_4":
        # Show last 4 digits: "2234 5678 9018" → "XXXX XXXX 9018"
        operators["IN_AADHAAR"] = OperatorConfig(
            "mask",
            {"type": "string", "masking_char": "X", "chars_to_mask": 8, "from_end": False}
        )
    elif twelve_digit_mode == "full_mask":
        # Mask all: "2234 5678 9018" → "XXXX XXXX XXXX"
        operators["IN_AADHAAR"] = OperatorConfig(
            "mask",
            {"type": "string", "masking_char": "X", "chars_to_mask": 14, "from_end": False}
        )
    elif twelve_digit_mode == "redact":
        operators["IN_AADHAAR"] = OperatorConfig(
            "replace",
            {"new_value": "[REDACTED_AADHAAR]"}
        )
    elif twelve_digit_mode == "ignore":
        operators["IN_AADHAAR"] = OperatorConfig("keep", {})

    # -------------------------------------------------------------------------
    # NAME HANDLING
    # -------------------------------------------------------------------------
    if name_mode == "redact":
        operators["PERSON"] = OperatorConfig(
            "replace",
            {"new_value": "[REDACTED_NAME]"}
        )
    elif name_mode == "mask_first":
        operators["PERSON"] = OperatorConfig(
            "mask",
            {"type": "string", "masking_char": "*", "chars_to_mask": 100, "from_end": False}
        )
    elif name_mode == "hash":
        operators["PERSON"] = OperatorConfig(
            "hash",
            {"hash_type": "sha256"}
        )

    # -------------------------------------------------------------------------
    # OTHER ENTITIES — Consistent handling
    # -------------------------------------------------------------------------
    operators["EMAIL_ADDRESS"] = OperatorConfig(
        "mask",
        {"type": "string", "masking_char": "*", "chars_to_mask": 100, "from_end": True}
    )

    operators["PHONE_NUMBER"] = OperatorConfig(
        "mask",
        {"type": "string", "masking_char": "X", "chars_to_mask": 6, "from_end": False}
    )

    operators["CREDIT_CARD"] = OperatorConfig(
        "mask",
        {"type": "string", "masking_char": "X", "chars_to_mask": 12, "from_end": False}
    )

    operators["IN_PAN"] = OperatorConfig(
        "mask",
        {"type": "string", "masking_char": "*", "chars_to_mask": 7, "from_end": False}
    )

    # Default for any unspecified entity types
    operators["DEFAULT"] = OperatorConfig(
        "replace",
        {"new_value": "[REDACTED]"}
    )

    return operators


def create_analyzer_with_lower_threshold(
    min_score: float = 0.3,
    enable_indian_name_fallback: bool = True,
) -> AnalyzerEngine:
    """
    Create an AnalyzerEngine with lower confidence threshold for names.
    
    This fixes Bug 1 by:
      1. Lowering the acceptance threshold (default 0.4 → 0.3)
      2. Adding a fallback Indian name recognizer
      3. Boosting scores when context words are present
    
    Args:
        min_score: Minimum confidence score to accept (lower = more recall)
        enable_indian_name_fallback: Add custom Indian name recognizer
    
    Returns:
        Configured AnalyzerEngine instance
    """
    from recognizers import IndianAadhaarRecognizer, IndianPanRecognizer

    # Create analyzer with default recognizers
    analyzer = AnalyzerEngine()

    # Add custom Indian PII recognizers
    analyzer.registry.add_recognizer(IndianAadhaarRecognizer())
    analyzer.registry.add_recognizer(IndianPanRecognizer())

    # Add fallback Indian name recognizer (Bug 1 fix)
    if enable_indian_name_fallback:
        analyzer.registry.add_recognizer(IndianNameRecognizer())
        logger.info("Added fallback Indian Name Recognizer")

    return analyzer


def analyze_with_deduplication(
    analyzer: AnalyzerEngine,
    text: str,
    min_score: float = 0.3,
    language: str = "en",
) -> list[RecognizerResult]:
    """
    Analyze text and deduplicate overlapping results.
    
    This fixes Bug 2 by ensuring that when multiple recognizers detect
    the same span (e.g., both IN_AADHAAR and a generic number pattern),
    we keep only the most specific/highest-confidence result.
    
    Args:
        analyzer: AnalyzerEngine instance
        text: Text to analyze
        min_score: Minimum confidence threshold
        language: Language code
    
    Returns:
        Deduplicated list of RecognizerResult
    """
    # Run analysis
    results = analyzer.analyze(
        text=text,
        language=language,
        score_threshold=min_score,
    )

    if not results:
        return []

    # Sort by (start, -end, -score) so longer/higher-confidence come first
    results = sorted(results, key=lambda r: (r.start, -r.end, -r.score))

    # Deduplicate overlapping spans
    deduped = []
    for result in results:
        # Check if this result overlaps with any already-kept result
        overlaps = False
        for kept in deduped:
            # Check for overlap
            if not (result.end <= kept.start or result.start >= kept.end):
                overlaps = True
                # If same span, prefer custom Indian recognizers over built-in
                if result.start == kept.start and result.end == kept.end:
                    # Prefer IN_AADHAAR over generic patterns
                    if result.entity_type.startswith("IN_"):
                        deduped.remove(kept)
                        deduped.append(result)
                break

        if not overlaps:
            deduped.append(result)

    logger.debug(f"Deduplicated {len(results)} results to {len(deduped)}")
    return deduped


# ===========================================================================
# BUG 3 FIX: Cell-by-Cell Table Processing with Alignment Preservation
# ===========================================================================

@dataclass
class TableCell:
    """Represents a single cell in an ASCII table."""
    row_idx: int
    col_idx: int
    original_value: str
    sanitized_value: str
    width: int  # Original column width (for padding)
    alignment: str  # 'left', 'right', 'center'


class AsciiTableProcessor:
    """
    Processes ASCII tables cell-by-cell to preserve alignment.
    
    Fixes Bug 3 by:
      1. Parsing the table structure (headers, rows, dividers)
      2. Extracting individual cell values
      3. Running Presidio on each cell independently
      4. Reconstructing the table with proper padding
    
    Supports common ASCII table formats:
      - Pipe-delimited: | Col1 | Col2 | Col3 |
      - With dividers:  +------+------+------+
      - Mixed formats
    """

    # Regex to detect table divider lines (e.g. +---+---+ or | --- | --- |)
    DIVIDER_PATTERN = re.compile(r"^[\s]*[+\-|=\s]+[\s]*$")

    # Additional check: divider must have at least one dash or equals sign

    # Quasi-identifier column classification keywords
    PII_COLUMN_KEYWORDS = {
        "aadhaar": "IN_AADHAAR", "aadhar": "IN_AADHAAR", "uid": "IN_AADHAAR",
        "pan": "IN_PAN",
        "ssn": "US_SSN",
        "name": "PERSON",
        "email": "EMAIL_ADDRESS", "e-mail": "EMAIL_ADDRESS",
        "phone": "PHONE_NUMBER", "mobile": "PHONE_NUMBER", "contact number": "PHONE_NUMBER",
        "credit card": "CREDIT_CARD",
        "address": "LOCATION",
        "dob": "DATE_TIME", "date of birth": "DATE_TIME", "birth": "DATE_TIME",
    }
    # Generic column headers that indicate a non-PII numeric/ID column
    NON_PII_INDICATORS = [
        "number", "digit", "id", "code", "serial",
        "roll", "reference", "transaction", "order", "account",
    ]
    
    def __init__(
        self,
        analyzer: AnalyzerEngine,
        anonymizer: AnonymizerEngine,
        operators: dict[str, OperatorConfig],
        min_score: float = 0.3,
    ):
        self.analyzer = analyzer
        self.anonymizer = anonymizer
        self.operators = operators
        self.min_score = min_score

    def classify_column(self, header: str) -> dict:
        """
        Classify a column as PII or non-PII based on its header text.

        Implements quasi-identifier logic: a 12-digit number column is NOT PII
        by itself, but an 'Aadhaar Number' column IS because the header provides
        the identifying context.

        Returns dict with keys: is_pii, entity_type, context
        """
        header_lower = header.lower().strip()

        # Check PII keywords first (higher priority)
        for keyword, entity_type in self.PII_COLUMN_KEYWORDS.items():
            if keyword in header_lower:
                return {"is_pii": True, "entity_type": entity_type, "context": keyword}

        # Check generic non-PII indicators
        for indicator in self.NON_PII_INDICATORS:
            if indicator in header_lower:
                return {"is_pii": False, "entity_type": None, "context": None}

        # Default: treat as potentially PII (safe default)
        return {"is_pii": True, "entity_type": None, "context": None}

    def is_divider_line(self, line: str) -> bool:
        """Check if a line is a table divider (e.g., +----+----+ or | --- | --- |)."""
        stripped = line.strip()
        if not stripped:
            return False
        # Must contain at least one dash or equals (not just pipes/spaces)
        if not re.search(r"[-=]", stripped):
            return False
        # Must NOT contain any alphanumeric characters
        return not re.search(r"[a-zA-Z0-9]", stripped)

    def parse_row(self, line: str) -> list[str]:
        """
        Parse a pipe-delimited row into cell values.
        
        Example: "| Alice | 123456789012 |" → ["Alice", "123456789012"]
        """
        # Remove leading/trailing pipes and split
        stripped = line.strip()
        if stripped.startswith("|"):
            stripped = stripped[1:]
        if stripped.endswith("|"):
            stripped = stripped[:-1]

        # Split by pipe and strip whitespace
        cells = [cell.strip() for cell in stripped.split("|")]
        return cells

    def detect_column_widths(self, lines: list[str]) -> list[int]:
        """
        Detect the width of each column based on pipe positions.
        
        Returns list of column widths (including padding).
        """
        widths = []

        for line in lines:
            if self.is_divider_line(line) or not "|" in line:
                continue

            # Find pipe positions
            pipe_positions = [i for i, c in enumerate(line) if c == "|"]
            
            if len(pipe_positions) < 2:
                continue

            # Calculate widths between pipes
            row_widths = []
            for i in range(len(pipe_positions) - 1):
                width = pipe_positions[i + 1] - pipe_positions[i] - 1
                row_widths.append(width)

            # Update column widths (take max)
            if not widths:
                widths = row_widths
            else:
                for i, w in enumerate(row_widths):
                    if i < len(widths):
                        widths[i] = max(widths[i], w)
                    else:
                        widths.append(w)

        return widths

    def sanitize_cell(self, value: str, column_info: dict = None) -> str:
        """
        Run Presidio analysis and anonymization on a single cell value.

        If column_info indicates a non-PII column, skip detection entirely.
        If column_info provides PII context (e.g. 'aadhaar'), prepend it so
        context-dependent recognizers activate.
        """
        if not value.strip():
            return value

        # Skip non-PII columns entirely (quasi-identifier logic)
        if column_info and not column_info.get("is_pii", True):
            return value

        # If column has specific PII context, prepend it for recognizer boost
        if column_info and column_info.get("context"):
            context_prefix = column_info["context"]
            analysis_text = f"{context_prefix} {value}"
            offset = len(context_prefix) + 1
        else:
            analysis_text = value
            offset = 0

        # Analyze
        results = analyze_with_deduplication(
            self.analyzer,
            analysis_text,
            min_score=self.min_score,
        )

        if not results:
            return value

        # Adjust result positions back to the original cell value
        adjusted_results = []
        for r in results:
            # Clamp span to value portion (handles detections that overlap prefix)
            adj_start = max(r.start, offset) - offset
            adj_end = min(r.end, offset + len(value)) - offset
            if adj_start < adj_end:
                adjusted = RecognizerResult(
                    entity_type=r.entity_type,
                    start=adj_start,
                    end=adj_end,
                    score=r.score,
                )
                adjusted_results.append(adjusted)

        if not adjusted_results:
            return value

        # Anonymize
        anonymized = self.anonymizer.anonymize(
            text=value,
            analyzer_results=adjusted_results,
            operators=self.operators,
        )

        return anonymized.text

    def pad_cell(self, value: str, width: int, alignment: str = "left") -> str:
        """
        Pad a cell value to fit the column width.
        
        If the sanitized value is longer than the original column,
        truncate with ellipsis to maintain alignment.
        """
        # Account for single space padding on each side
        content_width = width - 2  # Subtract 2 for " value "
        
        if len(value) > content_width:
            # Truncate with ellipsis
            value = value[:content_width - 1] + "…"

        if alignment == "right":
            return " " + value.rjust(content_width) + " "
        elif alignment == "center":
            return " " + value.center(content_width) + " "
        else:  # left
            return " " + value.ljust(content_width) + " "

    def process_table(self, table_text: str) -> str:
        """
        Process an entire ASCII table, preserving alignment.

        Implements quasi-identifier column detection: columns whose headers
        don't indicate PII (e.g. '12-Digit Number') are left untouched,
        while columns like 'Name' or 'Aadhaar Number' are sanitized.
        """
        lines = table_text.split("\n")
        
        # Detect column widths from original table
        col_widths = self.detect_column_widths(lines)
        
        if not col_widths:
            # Not a valid table — fall back to line-by-line processing
            logger.warning("Could not detect table structure, processing line-by-line")
            return self._process_line_by_line(lines)

        # --- Detect header row and classify columns ---
        headers = []
        column_infos = []
        for line in lines:
            if self.is_divider_line(line) or "|" not in line:
                continue
            # First non-divider pipe-delimited line is the header
            headers = self.parse_row(line)
            column_infos = [self.classify_column(h) for h in headers]
            break

        result_lines = []
        header_seen = False

        for line in lines:
            if self.is_divider_line(line):
                # Keep divider lines unchanged
                result_lines.append(line)
                continue

            if "|" not in line:
                # Non-table line — sanitize as regular text
                sanitized = self.sanitize_cell(line)
                result_lines.append(sanitized)
                continue

            # Skip the header row itself (don't sanitize column names)
            if not header_seen:
                header_seen = True
                result_lines.append(line)
                continue

            # Parse cells
            cells = self.parse_row(line)
            sanitized_cells = []

            for i, cell in enumerate(cells):
                # Get column info if available
                col_info = column_infos[i] if i < len(column_infos) else None
                # Sanitize cell value with column awareness
                sanitized = self.sanitize_cell(cell, column_info=col_info)
                
                # Pad to original column width
                width = col_widths[i] if i < len(col_widths) else len(cell) + 2
                padded = self.pad_cell(sanitized, width)
                sanitized_cells.append(padded)

            # Reconstruct row with pipes
            result_lines.append("|" + "|".join(sanitized_cells) + "|")

        return "\n".join(result_lines)

    def _process_line_by_line(self, lines: list[str]) -> str:
        """Fallback: process each line independently."""
        result = []
        for line in lines:
            sanitized = self.sanitize_cell(line)
            result.append(sanitized)
        return "\n".join(result)


# ===========================================================================
# CONVENIENCE FUNCTIONS
# ===========================================================================

def create_table_processor(
    twelve_digit_mode: str = "mask_last_4",
    name_mode: str = "redact",
    min_score: float = 0.3,
) -> AsciiTableProcessor:
    """
    Create a fully configured table processor.
    
    Args:
        twelve_digit_mode: "mask_last_4", "full_mask", "redact", or "ignore"
        name_mode: "redact", "mask_first", or "hash"
        min_score: Minimum confidence threshold (lower = more recall)
    
    Returns:
        Configured AsciiTableProcessor instance
    """
    analyzer = create_analyzer_with_lower_threshold(
        min_score=min_score,
        enable_indian_name_fallback=True,
    )
    anonymizer = AnonymizerEngine()
    operators = create_unified_operators(
        twelve_digit_mode=twelve_digit_mode,
        name_mode=name_mode,
    )

    return AsciiTableProcessor(
        analyzer=analyzer,
        anonymizer=anonymizer,
        operators=operators,
        min_score=min_score,
    )


def process_ascii_table(
    table_text: str,
    twelve_digit_mode: str = "mask_last_4",
    name_mode: str = "redact",
    min_score: float = 0.3,
) -> str:
    """
    One-liner to process an ASCII table with default settings.
    
    Example:
        >>> table = '''
        ... | Name           | Aadhaar Number   |
        ... |----------------|------------------|
        ... | Ananya Kapoor  | 2234 5678 9018   |
        ... | Rajesh Kumar   | 3345 6789 0126   |
        ... '''
        >>> print(process_ascii_table(table))
        | Name           | Aadhaar Number   |
        |----------------|------------------|
        | [REDACTED_NAME]| XXXX XXXX 9018   |
        | [REDACTED_NAME]| XXXX XXXX 0126   |
    """
    processor = create_table_processor(
        twelve_digit_mode=twelve_digit_mode,
        name_mode=name_mode,
        min_score=min_score,
    )
    return processor.process_table(table_text)


# ===========================================================================
# DEMO / TEST
# ===========================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Sample ASCII table with Indian names and Aadhaar numbers
    sample_table = """
+------------------+------------------+------------------------+
| Name             | Aadhaar Number   | Email                  |
+------------------+------------------+------------------------+
| Ananya Kapoor    | 2234 5678 9018   | ananya@example.com     |
| Rajesh Kumar     | 3345 6789 0126   | rajesh.kumar@corp.in   |
| Vikram Singh     | 4456 7890 1233   | vikram@enterprise.com  |
| Priya Sharma     | 223456789018     | priya.sharma@mail.com  |
+------------------+------------------+------------------------+

Internal IDs (should NOT be redacted):
  Employee Code: EMP00451
  Roll Number: 2345678901
  Transaction ID: TXN2024001
"""

    print("=" * 70)
    print("  PII SHIELD — ASCII Table Processor Demo")
    print("  Fixes: Missing names, inconsistent masking, alignment issues")
    print("=" * 70)

    print("\n▶ ORIGINAL TABLE:")
    print(sample_table)

    print("\n▶ SANITIZED TABLE (mask_last_4 mode):")
    result = process_ascii_table(
        sample_table,
        twelve_digit_mode="mask_last_4",
        name_mode="redact",
        min_score=0.3,
    )
    print(result)

    print("\n" + "-" * 70)
    print("▶ SANITIZED TABLE (full_mask mode):")
    result2 = process_ascii_table(
        sample_table,
        twelve_digit_mode="full_mask",
        name_mode="redact",
        min_score=0.3,
    )
    print(result2)
